"""Fetch and normalize current UDM Pro state into diffable data structures.

Pulls zones, networks, and firewall policies from the live UDM Pro via
api_client.py and returns a CurrentState object whose fields use names
(not UUIDs) so they can be compared directly against desired.yml.

Usage:
    python pull_state.py
"""

import os
from dataclasses import dataclass

from api_client import UDMApiClient, load_env


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ZoneState:
    name: str
    id: str
    network_names: list[str]   # resolved from networkIds via network lookup
    system: bool               # True if metadata.origin == "SYSTEM_DEFINED"


@dataclass
class PolicyState:
    name: str
    id: str
    action: str                # "allow" or "block" (lowercased from action.type)
    source_zone: str           # zone NAME (resolved from source.zoneId)
    destination_zone: str      # zone NAME (resolved from destination.zoneId)
    protocol: str              # "all", "tcp", "udp", "tcp_udp" (normalized)
    destination_ports: list[int]  # sorted list of port numbers, empty for allow-all
    enabled: bool
    allow_return_traffic: bool
    index: int
    origin: str                # "USER_DEFINED", "SYSTEM_DEFINED", "DERIVED"


@dataclass
class PortForwardState:
    name: str
    id: str
    enabled: bool
    protocol: str           # "tcp", "udp", or "tcp_udp"
    wan_port: str           # external port (string — can be range "8080:8090")
    forward_ip: str         # internal destination IP
    forward_port: str       # internal destination port
    interface: str           # "wan", "wan2", or "both"


@dataclass
class CurrentState:
    zones: dict[str, ZoneState]           # zone name -> ZoneState
    policies: list[PolicyState]           # ALL policies (caller filters by origin)
    port_forwards: dict[str, PortForwardState]  # name -> PortForwardState
    networks: dict[str, str]              # network name -> network id
    zone_ids: dict[str, str]              # zone name -> zone id
    network_ids_to_names: dict[str, str]  # network id -> network name
    zone_ids_to_names: dict[str, str]     # zone id -> zone name


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def _normalize_protocol(ip_scope: dict) -> str:
    """Extract a canonical protocol string from the ipProtocolScope block.

    Rules:
    - No protocolFilter key present         → "all"
    - type == "NAMED_PROTOCOL"              → lowercase protocol.name  (e.g. "tcp")
    - type == "PRESET"                      → lowercase preset.name    (e.g. "tcp_udp")
    """
    proto_filter = ip_scope.get("protocolFilter")
    if proto_filter is None:
        return "all"

    filter_type = proto_filter.get("type")
    if filter_type == "NAMED_PROTOCOL":
        return proto_filter["protocol"]["name"].lower()
    if filter_type == "PRESET":
        return proto_filter["preset"]["name"].lower()

    # Unexpected filter type — return raw for visibility
    return filter_type.lower() if filter_type else "all"


def _normalize_ports(destination: dict) -> list[int]:
    """Extract a sorted list of port numbers from the destination block.

    Returns an empty list when no trafficFilter is present (allow-all).
    """
    traffic_filter = destination.get("trafficFilter")
    if traffic_filter is None:
        return []

    port_filter = traffic_filter.get("portFilter", {})
    items = port_filter.get("items", [])
    return sorted(item["value"] for item in items if "value" in item)


def _normalize_policy(raw: dict, zone_ids_to_names: dict[str, str]) -> PolicyState:
    """Convert a raw API policy dict into a PolicyState."""
    action_block = raw.get("action", {})
    source_block = raw.get("source", {})
    dest_block = raw.get("destination", {})
    ip_scope = raw.get("ipProtocolScope", {})
    metadata = raw.get("metadata", {})

    source_zone_id = source_block.get("zoneId", "")
    dest_zone_id = dest_block.get("zoneId", "")

    return PolicyState(
        name=raw.get("name", ""),
        id=raw.get("id", ""),
        action=action_block.get("type", "").lower(),  # "allow" or "block"
        source_zone=zone_ids_to_names.get(source_zone_id, source_zone_id),
        destination_zone=zone_ids_to_names.get(dest_zone_id, dest_zone_id),
        protocol=_normalize_protocol(ip_scope),
        destination_ports=_normalize_ports(dest_block),
        enabled=raw.get("enabled", True),
        allow_return_traffic=action_block.get("allowReturnTraffic", True),
        index=raw.get("index", 0),
        origin=metadata.get("origin", ""),
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def pull_current_state(client: UDMApiClient) -> CurrentState:
    """Fetch and normalize current UDM state.

    Makes three API calls (networks, zones, policies) and builds all lookup
    tables before normalizing so every ID→name resolution is in one place.
    """
    # --- Networks -----------------------------------------------------------
    raw_networks = client.list_networks()

    # name -> id  (used by diff engine to resolve desired network names)
    networks: dict[str, str] = {}
    # id -> name  (used to resolve networkIds on zones)
    network_ids_to_names: dict[str, str] = {}

    for net in raw_networks:
        nid = net.get("id", "")
        name = net.get("name", "")
        networks[name] = nid
        network_ids_to_names[nid] = name

    # --- Zones --------------------------------------------------------------
    raw_zones = client.list_zones()

    zones: dict[str, ZoneState] = {}
    zone_ids: dict[str, str] = {}
    zone_ids_to_names: dict[str, str] = {}

    for z in raw_zones:
        zid = z.get("id", "")
        name = z.get("name", "")
        metadata = z.get("metadata", {})
        network_ids = z.get("networkIds", [])

        zone_ids[name] = zid
        zone_ids_to_names[zid] = name

        zones[name] = ZoneState(
            name=name,
            id=zid,
            network_names=[
                network_ids_to_names.get(nid, nid) for nid in network_ids
            ],
            system=metadata.get("origin") == "SYSTEM_DEFINED",
        )

    # --- Policies -----------------------------------------------------------
    # Zone lookup must be complete before normalizing policies.
    raw_policies = client.list_policies()

    policies: list[PolicyState] = [
        _normalize_policy(p, zone_ids_to_names) for p in raw_policies
    ]

    # Sort by index so callers get a deterministic ordering
    policies.sort(key=lambda p: p.index)

    # --- Port Forwards ------------------------------------------------------
    raw_port_forwards = client.list_port_forwards()

    port_forwards: dict[str, PortForwardState] = {}
    for pf in raw_port_forwards:
        name = pf.get("name", "")
        port_forwards[name] = PortForwardState(
            name=name,
            id=pf.get("_id", ""),
            enabled=pf.get("enabled", True),
            protocol=pf.get("proto", "tcp"),
            wan_port=str(pf.get("dst_port", "")),
            forward_ip=pf.get("fwd", ""),
            forward_port=str(pf.get("fwd_port", "")),
            interface=pf.get("pfwd_interface", "wan"),
        )

    return CurrentState(
        zones=zones,
        policies=policies,
        port_forwards=port_forwards,
        networks=networks,
        zone_ids=zone_ids,
        network_ids_to_names=network_ids_to_names,
        zone_ids_to_names=zone_ids_to_names,
    )


# ---------------------------------------------------------------------------
# Smoke test / summary printer
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    load_env()

    host = os.environ.get("UDM_HOST")
    api_key = os.environ.get("UI_API_KEY")
    if not host:
        raise SystemExit("UDM_HOST is not set.")
    if not api_key:
        raise SystemExit("UI_API_KEY is not set.")

    client = UDMApiClient(host=host, api_key=api_key)
    state = pull_current_state(client)

    # --- Zone summary -------------------------------------------------------
    print(f"\nZones ({len(state.zones)}):")
    for name, z in sorted(state.zones.items()):
        tag = " [system]" if z.system else ""
        nets = ", ".join(z.network_names) if z.network_names else "(none)"
        print(f"  {name}{tag}: {nets}")

    # --- USER_DEFINED policy summary ----------------------------------------
    user_policies = [p for p in state.policies if p.origin == "USER_DEFINED"]
    print(f"\nUSER_DEFINED policies ({len(user_policies)}):")
    for p in user_policies:
        ports = f"  ports={p.destination_ports}" if p.destination_ports else ""
        print(
            f"  [{p.index}] {p.name}"
            f"\n        {p.source_zone} -> {p.destination_zone}"
            f"  proto={p.protocol}{ports}"
        )

    # --- Totals -------------------------------------------------------------
    by_origin: dict[str, int] = {}
    for p in state.policies:
        by_origin[p.origin] = by_origin.get(p.origin, 0) + 1

    print("\nPolicy totals:")
    for origin, count in sorted(by_origin.items()):
        print(f"  {origin}: {count}")
    print(f"  TOTAL: {len(state.policies)}")

    print(f"\nNetworks: {len(state.networks)}")

    # --- Port forward summary -----------------------------------------------
    print(f"\nPort forwards ({len(state.port_forwards)}):")
    for name, pf in sorted(state.port_forwards.items()):
        status = "enabled" if pf.enabled else "disabled"
        print(f"  {pf.name}: {pf.protocol}/{pf.wan_port} -> {pf.forward_ip}:{pf.forward_port}  [{status}]")
