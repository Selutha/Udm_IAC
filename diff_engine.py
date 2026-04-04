"""Diff engine for the UDM Pro IaC reconciler.

Parses desired.yml into a DesiredState, compares it against the CurrentState
produced by pull_state.py, and emits a Changeset describing every create,
update, and delete needed to bring the UDM Pro into alignment.

Usage:
    python diff_engine.py
"""

import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field

import yaml

from api_client import UDMApiClient, load_env
from pull_state import CurrentState, pull_current_state


# ---------------------------------------------------------------------------
# Desired-state data structures
# ---------------------------------------------------------------------------

@dataclass
class DesiredZone:
    name: str
    system: bool                  # True = SYSTEM_DEFINED; don't create/delete
    network_names: list[str]      # sorted


@dataclass
class DesiredPolicy:
    name: str
    action: str                   # "allow" or "block"
    source_zone: str
    destination_zone: str
    protocol: str                 # "all", "tcp", "udp", "tcp_udp"
    destination_ports: list[int]  # sorted; empty = allow-all
    enabled: bool = True
    allow_return_traffic: bool = True


@dataclass
class DesiredState:
    zones: dict[str, DesiredZone]   # zone name -> DesiredZone
    policies: list[DesiredPolicy]   # in desired evaluation order
    index_base: int
    index_step: int
    absent_zones: list[str] = field(default_factory=list)      # zone names to delete
    absent_policies: list[str] = field(default_factory=list)    # policy names to delete


# ---------------------------------------------------------------------------
# Changeset data structures
# ---------------------------------------------------------------------------

@dataclass
class ZoneChange:
    name: str
    zone_id: str | None   # None for creates
    action: str           # "create", "update", "delete"
    data: dict            # full API payload for create/update; {} for delete


@dataclass
class PolicyChange:
    name: str
    policy_id: str | None   # None for creates
    action: str             # "create", "update", "delete"
    data: dict              # full API payload for create/update; {} for delete


@dataclass
class ReorderEntry:
    source_zone: str            # zone name (for display)
    source_zone_id: str         # zone UUID (for API call)
    destination_zone: str       # zone name (for display)
    destination_zone_id: str    # zone UUID (for API call)
    ordered_policy_ids: list[str]  # desired order of existing policy IDs
    has_pending_creates: bool = False  # True if zone-pair also has new policies


@dataclass
class Changeset:
    zones_to_create: list[ZoneChange] = field(default_factory=list)
    zones_to_update: list[ZoneChange] = field(default_factory=list)
    zones_to_delete: list[ZoneChange] = field(default_factory=list)
    policies_to_create: list[PolicyChange] = field(default_factory=list)
    policies_to_update: list[PolicyChange] = field(default_factory=list)
    policies_to_delete: list[PolicyChange] = field(default_factory=list)
    needs_reorder: bool = False
    reorder_entries: list[ReorderEntry] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return (
            not self.zones_to_create
            and not self.zones_to_update
            and not self.zones_to_delete
            and not self.policies_to_create
            and not self.policies_to_update
            and not self.policies_to_delete
            and not self.needs_reorder
        )


# ---------------------------------------------------------------------------
# Parse desired.yml
# ---------------------------------------------------------------------------

def parse_desired(yaml_path: str) -> DesiredState:
    """Load and validate desired.yml, returning a DesiredState."""
    with open(yaml_path) as fh:
        raw = yaml.safe_load(fh)

    # --- Zones ---------------------------------------------------------------
    zones: dict[str, DesiredZone] = {}
    for zone_name, zone_cfg in (raw.get("zones") or {}).items():
        zone_name = str(zone_name)
        cfg = zone_cfg or {}
        system = bool(cfg.get("system", False))
        networks = sorted(str(n) for n in (cfg.get("networks") or []))
        zones[zone_name] = DesiredZone(
            name=zone_name,
            system=system,
            network_names=networks,
        )

    # --- Policies ------------------------------------------------------------
    policy_section = raw.get("policies") or {}
    index_base = int(policy_section.get("index_base", 10000))
    index_step = int(policy_section.get("index_step", 1))

    policies: list[DesiredPolicy] = []
    for rule in (policy_section.get("rules") or []):
        # destination_port is a comma-separated string of port numbers
        raw_port = rule.get("destination_port", "")
        if raw_port:
            dest_ports = sorted(int(p.strip()) for p in str(raw_port).split(",") if p.strip())
        else:
            dest_ports = []

        policies.append(DesiredPolicy(
            name=str(rule["name"]),
            action=str(rule.get("action", "allow")).lower(),
            source_zone=str(rule["source"]),
            destination_zone=str(rule["destination"]),
            protocol=str(rule.get("protocol", "all")).lower(),
            destination_ports=dest_ports,
            enabled=bool(rule.get("enabled", True)),
            allow_return_traffic=bool(rule.get("allow_return_traffic", True)),
        ))

    absent_section = raw.get("absent") or {}
    absent_zones = [str(z) for z in (absent_section.get("zones") or [])]
    absent_policies = [str(p) for p in (absent_section.get("policies") or [])]

    return DesiredState(
        zones=zones,
        policies=policies,
        index_base=index_base,
        index_step=index_step,
        absent_zones=absent_zones,
        absent_policies=absent_policies,
    )


# ---------------------------------------------------------------------------
# API payload builders
# ---------------------------------------------------------------------------

def _build_protocol_filter(protocol: str) -> dict | None:
    """Return the protocolFilter block, or None when protocol is 'all'."""
    if protocol == "all":
        return None
    if protocol == "tcp":
        return {
            "type": "NAMED_PROTOCOL",
            "protocol": {"name": "TCP"},
            "matchOpposite": False,
        }
    if protocol == "udp":
        return {
            "type": "NAMED_PROTOCOL",
            "protocol": {"name": "UDP"},
            "matchOpposite": False,
        }
    if protocol == "tcp_udp":
        return {
            "type": "PRESET",
            "preset": {"name": "TCP_UDP"},
        }
    raise ValueError(f"Unknown protocol: {protocol!r}")


def _build_traffic_filter(ports: list[int]) -> dict | None:
    """Return the trafficFilter block, or None when ports is empty."""
    if not ports:
        return None
    return {
        "type": "PORT",
        "portFilter": {
            "type": "PORTS",
            "matchOpposite": False,
            "items": [{"type": "PORT_NUMBER", "value": p} for p in ports],
        },
    }


def _build_policy_payload(dp: DesiredPolicy, current: CurrentState) -> dict:
    """Construct the full v1 API payload for a policy create or update."""
    source_zone_id = current.zone_ids.get(dp.source_zone, "")
    dest_zone_id = current.zone_ids.get(dp.destination_zone, "")

    action_type = "ALLOW" if dp.action == "allow" else "BLOCK"

    ip_scope: dict = {"ipVersion": "IPV4_AND_IPV6"}
    proto_filter = _build_protocol_filter(dp.protocol)
    if proto_filter is not None:
        ip_scope["protocolFilter"] = proto_filter

    destination: dict = {"zoneId": dest_zone_id}
    traffic_filter = _build_traffic_filter(dp.destination_ports)
    if traffic_filter is not None:
        destination["trafficFilter"] = traffic_filter

    return {
        "enabled": dp.enabled,
        "name": dp.name,
        "action": {
            "type": action_type,
            "allowReturnTraffic": dp.allow_return_traffic,
        },
        "source": {"zoneId": source_zone_id},
        "destination": destination,
        "ipProtocolScope": ip_scope,
        "loggingEnabled": False,
    }


def _build_zone_payload(dz: DesiredZone, current: CurrentState) -> dict:
    """Construct the API payload for a zone create or update."""
    # Resolve each desired network name to its UUID.  Unknown names are passed
    # through as-is so the error surfaces clearly from the API rather than
    # silently dropping networks.
    network_ids = [current.networks.get(n, n) for n in dz.network_names]
    return {"name": dz.name, "networkIds": network_ids}


# ---------------------------------------------------------------------------
# Policy field comparison
# ---------------------------------------------------------------------------

def _policy_matches(dp: DesiredPolicy, cp) -> bool:
    """Return True if the desired and current policy have identical fields."""
    return (
        dp.action == cp.action
        and dp.source_zone == cp.source_zone
        and dp.destination_zone == cp.destination_zone
        and dp.protocol == cp.protocol
        and sorted(dp.destination_ports) == sorted(cp.destination_ports)
        and dp.enabled == cp.enabled
        and dp.allow_return_traffic == cp.allow_return_traffic
    )


# ---------------------------------------------------------------------------
# Core diff algorithm
# ---------------------------------------------------------------------------

def compute_diff(desired: DesiredState, current: CurrentState) -> Changeset:
    """Compare desired state against current state and return a Changeset."""
    cs = Changeset()

    # -----------------------------------------------------------------------
    # Zone diff
    # -----------------------------------------------------------------------
    for zone_name, dz in desired.zones.items():
        if zone_name not in current.zones:
            if dz.system:
                # A system zone that doesn't exist yet is a config error —
                # we never create SYSTEM_DEFINED zones; raise immediately.
                raise ValueError(
                    f"Zone {zone_name!r} is marked system:true in desired.yml "
                    f"but does not exist on the UDM Pro.  "
                    f"System zones are created by UniFi, not by IaC."
                )
            cs.zones_to_create.append(ZoneChange(
                name=zone_name,
                zone_id=None,
                action="create",
                data=_build_zone_payload(dz, current),
            ))
        else:
            cz = current.zones[zone_name]
            if sorted(dz.network_names) != sorted(cz.network_names):
                cs.zones_to_update.append(ZoneChange(
                    name=zone_name,
                    zone_id=cz.id,
                    action="update",
                    data=_build_zone_payload(dz, current),
                ))

    # Zones present in current but absent from desired are intentionally
    # left untouched — only zones named in desired.yml are managed.

    # -----------------------------------------------------------------------
    # Policy diff
    # -----------------------------------------------------------------------
    # Index USER_DEFINED current policies by name for O(1) lookup.
    current_by_name: dict[str, object] = {
        p.name: p
        for p in current.policies
        if p.origin == "USER_DEFINED"
    }

    desired_names: set[str] = {dp.name for dp in desired.policies}

    for dp in desired.policies:
        if dp.name not in current_by_name:
            cs.policies_to_create.append(PolicyChange(
                name=dp.name,
                policy_id=None,
                action="create",
                data=_build_policy_payload(dp, current),
            ))
        else:
            cp = current_by_name[dp.name]
            if not _policy_matches(dp, cp):
                cs.policies_to_update.append(PolicyChange(
                    name=dp.name,
                    policy_id=cp.id,
                    action="update",
                    data=_build_policy_payload(dp, current),
                ))

    # Current USER_DEFINED policies not referenced in desired → delete
    for name, cp in current_by_name.items():
        if name not in desired_names:
            cs.policies_to_delete.append(PolicyChange(
                name=name,
                policy_id=cp.id,
                action="delete",
                data={},
            ))

    # -----------------------------------------------------------------------
    # Absent zones — explicitly declared for deletion
    # -----------------------------------------------------------------------
    existing_zone_deletes: set[str] = {z.name for z in cs.zones_to_delete}
    for name in desired.absent_zones:
        if name not in current.zones or name in existing_zone_deletes:
            continue
        cz = current.zones[name]
        if cz.system:
            raise ValueError(
                f"Zone {name!r} is listed in absent: but is a SYSTEM_DEFINED zone — "
                f"system zones cannot be deleted via IaC."
            )
        cs.zones_to_delete.append(ZoneChange(
            name=name,
            zone_id=cz.id,
            action="delete",
            data={},
        ))

    # -----------------------------------------------------------------------
    # Absent policies — explicitly declared for deletion
    # -----------------------------------------------------------------------
    existing_policy_deletes: set[str] = {p.name for p in cs.policies_to_delete}
    for name in desired.absent_policies:
        if name not in current_by_name or name in existing_policy_deletes:
            continue
        cp = current_by_name[name]
        cs.policies_to_delete.append(PolicyChange(
            name=name,
            policy_id=cp.id,
            action="delete",
            data={},
        ))

    # -----------------------------------------------------------------------
    # Policy ordering check — per zone-pair
    # -----------------------------------------------------------------------
    # The UDM ordering API is scoped to (source_zone, destination_zone) pairs.
    # For each pair, compare the desired sequence of existing policy IDs
    # against the current sequence (by index).  Emit a ReorderEntry for any
    # pair where the two differ.

    creating_names: set[str] = {c.name for c in cs.policies_to_create}
    deleting_names: set[str] = {c.name for c in cs.policies_to_delete}

    # Group desired policies by (source_zone, destination_zone)
    zone_pair_desired: dict[tuple[str, str], list] = defaultdict(list)
    for dp in desired.policies:
        zone_pair_desired[(dp.source_zone, dp.destination_zone)].append(dp)

    for (src_zone, dst_zone), dps in zone_pair_desired.items():
        # Desired order: IDs of policies that already exist and are staying
        desired_ids: list[str] = []
        for dp in dps:
            if dp.name in creating_names or dp.name in deleting_names:
                continue
            cp = current_by_name.get(dp.name)
            if cp is not None:
                desired_ids.append(cp.id)

        if len(desired_ids) < 2:
            continue  # nothing to reorder with 0 or 1 policies

        # Current order: same policies sorted by their live index
        current_in_pair = [
            p for p in current.policies
            if p.origin == "USER_DEFINED"
            and p.source_zone == src_zone
            and p.destination_zone == dst_zone
            and p.name not in deleting_names
        ]
        current_in_pair.sort(key=lambda p: p.index)
        current_ids = [p.id for p in current_in_pair]

        if current_ids != desired_ids:
            has_creates = any(dp.name in creating_names for dp in dps)
            cs.needs_reorder = True
            cs.reorder_entries.append(ReorderEntry(
                source_zone=src_zone,
                source_zone_id=current.zone_ids.get(src_zone, ""),
                destination_zone=dst_zone,
                destination_zone_id=current.zone_ids.get(dst_zone, ""),
                ordered_policy_ids=desired_ids,
                has_pending_creates=has_creates,
            ))

    return cs


# ---------------------------------------------------------------------------
# Safety checks
# ---------------------------------------------------------------------------

def safety_check(changeset: Changeset, desired: DesiredState) -> list[str]:
    """Validate a changeset for obviously dangerous operations.

    Returns a list of warning/error strings.  An empty list means the
    changeset is safe to apply without additional confirmation.

    Error strings are prefixed "ERROR:" and must block execution.
    Warning strings are prefixed "WARNING:" and should prompt for --force.
    """
    issues: list[str] = []

    # 1. Admin zone must never be deleted
    admin_deletes = [z for z in changeset.zones_to_delete if z.name == "Admin"]
    if admin_deletes:
        issues.append("ERROR: Admin zone is in the delete list — this would cause a lockout.")

    # 2. All Admin allow-all policies being deleted simultaneously
    #    Identify Admin allow-all policies in desired state so we know the
    #    universe of names to watch.  If every one of them is in the delete
    #    list, that's a lockout risk.
    admin_allow_all_desired = {
        dp.name
        for dp in desired.policies
        if dp.source_zone == "Admin" and dp.action == "allow" and not dp.destination_ports
    }
    deleting_policy_names = {c.name for c in changeset.policies_to_delete}
    if admin_allow_all_desired and admin_allow_all_desired.issubset(deleting_policy_names):
        issues.append(
            "ERROR: All Admin allow-all policies are being deleted simultaneously — "
            "this would prevent Admin zone from reaching any other zone."
        )

    # 3. Large-scale policy deletes
    if len(changeset.policies_to_delete) > 5:
        issues.append(
            f"WARNING: {len(changeset.policies_to_delete)} policies are queued for deletion. "
            f"Pass --force to proceed."
        )

    # 4. Large-scale zone deletes
    if len(changeset.zones_to_delete) > 2:
        issues.append(
            f"WARNING: {len(changeset.zones_to_delete)} zones are queued for deletion. "
            f"Pass --force to proceed."
        )

    return issues


# ---------------------------------------------------------------------------
# Changeset summary printer
# ---------------------------------------------------------------------------

def _print_changeset(cs: Changeset) -> None:
    """Print a human-readable summary of the changeset to stdout."""
    if cs.zones_to_create:
        print(f"\nZones to CREATE ({len(cs.zones_to_create)}):")
        for z in cs.zones_to_create:
            nets = z.data.get("networkIds", [])
            print(f"  + {z.name}  networkIds={nets}")

    if cs.zones_to_update:
        print(f"\nZones to UPDATE ({len(cs.zones_to_update)}):")
        for z in cs.zones_to_update:
            nets = z.data.get("networkIds", [])
            print(f"  ~ {z.name}  (id={z.zone_id})  networkIds={nets}")

    if cs.zones_to_delete:
        print(f"\nZones to DELETE ({len(cs.zones_to_delete)}):")
        for z in cs.zones_to_delete:
            print(f"  - {z.name}  (id={z.zone_id})")

    if cs.policies_to_create:
        print(f"\nPolicies to CREATE ({len(cs.policies_to_create)}):")
        for p in cs.policies_to_create:
            src = p.data.get("source", {}).get("zoneId", "?")
            dst = p.data.get("destination", {}).get("zoneId", "?")
            print(f"  + {p.name}  ({src} -> {dst})")

    if cs.policies_to_update:
        print(f"\nPolicies to UPDATE ({len(cs.policies_to_update)}):")
        for p in cs.policies_to_update:
            print(f"  ~ {p.name}  (id={p.policy_id})")

    if cs.policies_to_delete:
        print(f"\nPolicies to DELETE ({len(cs.policies_to_delete)}):")
        for p in cs.policies_to_delete:
            print(f"  - {p.name}  (id={p.policy_id})")

    if cs.needs_reorder:
        print(f"\nPolicy reorder ({len(cs.reorder_entries)} zone-pair(s)):")
        for e in cs.reorder_entries:
            tag = " [deferred — new policies pending]" if e.has_pending_creates else ""
            print(f"  ↕ {e.source_zone} -> {e.destination_zone}  ({len(e.ordered_policy_ids)} policies){tag}")


# ---------------------------------------------------------------------------
# __main__ — smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    load_env()

    host = os.environ.get("UDM_HOST")
    api_key = os.environ.get("UI_API_KEY")
    if not host:
        raise SystemExit("UDM_HOST is not set.")
    if not api_key:
        raise SystemExit("UI_API_KEY is not set.")

    desired_yml = os.path.join(os.path.dirname(__file__), "desired.yml")

    client = UDMApiClient(host=host, api_key=api_key)
    current = pull_current_state(client)
    desired = parse_desired(desired_yml)
    changeset = compute_diff(desired, current)

    issues = safety_check(changeset, desired)
    if issues:
        print("\nSafety check issues:")
        for issue in issues:
            print(f"  {issue}")
        has_errors = any(i.startswith("ERROR:") for i in issues)
        if has_errors:
            raise SystemExit("Aborting — safety check found errors.")

    if changeset.is_empty:
        print("No changes needed — desired state matches current state.")
        sys.exit(0)

    _print_changeset(changeset)
