"""Generate an Ansible playbook from a UDM Pro IaC changeset.

Builds the playbook as a Python data structure and serialises it with
yaml.dump() — no external Jinja2 template files needed.  The Changeset
already contains fully-resolved API payloads, so it IS the template data.

Usage:
    Called from reconcile.py; not normally invoked directly.
"""

import os
from datetime import datetime, timezone

import yaml

from diff_engine import Changeset

# The Ansible ubiquiti.unifi_api.network module auto-constructs the full URL:
#   {base_url}/proxy/network/integration{path}
# So base_url should be the bare host (e.g. https://192.168.0.1) and path
# should be the spec path (e.g. /v1/sites/{siteId}/firewall/policies).
_API_PATH_PREFIX = "/v1"


# ---------------------------------------------------------------------------
# YAML representer — keep dicts in insertion order, inline None/bool cleanly
# ---------------------------------------------------------------------------

class _OrderedDumper(yaml.Dumper):
    """Dumper subclass that:
    - preserves dict key insertion order
    - never adds the !!python/object tags
    - outputs strings that look like Jinja2 templates without quoting issues
    """
    pass


def _str_representer(dumper, data):
    # Force block-scalar for multi-line strings; plain scalar otherwise.
    # Jinja2 expressions such as "{{ lookup(...) }}" must stay as plain scalars
    # so Ansible can evaluate them — double braces would be double-quoted and
    # break if we used the default representer on them.
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_OrderedDumper.add_representer(str, _str_representer)
_OrderedDumper.add_representer(
    dict,
    lambda dumper, data: dumper.represent_mapping("tag:yaml.org,2002:map", data.items()),
)


def _dump(data) -> str:
    return yaml.dump(
        data,
        Dumper=_OrderedDumper,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )


# ---------------------------------------------------------------------------
# Task builders
# ---------------------------------------------------------------------------

def _zone_create_task(change) -> dict:
    """POST to firewall/zones — always starts with empty networkIds."""
    return {
        "name": f"Create zone: {change.name}",
        "ubiquiti.unifi_api.network": {
            "path": (
                f"{_API_PATH_PREFIX}/sites/{{{{ site_id }}}}/firewall/zones"
            ),
            "method": "POST",
            "body": change.data,
        },
    }


def _zone_update_task(change) -> dict:
    """PUT to firewall/zones/{id} — assigns networkIds."""
    return {
        "name": f"Update zone networks: {change.name}",
        "ubiquiti.unifi_api.network": {
            "path": (
                f"{_API_PATH_PREFIX}/sites/{{{{ site_id }}}}/firewall/zones/{change.zone_id}"
            ),
            "method": "PUT",
            "body": change.data,
        },
    }


def _zone_delete_task(change) -> dict:
    """DELETE firewall/zones/{id}."""
    return {
        "name": f"Delete zone: {change.name}",
        "ubiquiti.unifi_api.network": {
            "path": (
                f"{_API_PATH_PREFIX}/sites/{{{{ site_id }}}}/firewall/zones/{change.zone_id}"
            ),
            "method": "DELETE",
        },
    }


def _policy_create_task(change) -> dict:
    """POST to firewall/policies."""
    return {
        "name": f"Create policy: {change.name}",
        "ubiquiti.unifi_api.network": {
            "path": (
                f"{_API_PATH_PREFIX}/sites/{{{{ site_id }}}}/firewall/policies"
            ),
            "method": "POST",
            "body": change.data,
        },
    }


def _policy_update_task(change) -> dict:
    """PUT to firewall/policies/{id}."""
    return {
        "name": f"Update policy: {change.name}",
        "ubiquiti.unifi_api.network": {
            "path": (
                f"{_API_PATH_PREFIX}/sites/{{{{ site_id }}}}/firewall/policies/{change.policy_id}"
            ),
            "method": "PUT",
            "body": change.data,
        },
    }


def _policy_delete_task(change) -> dict:
    """DELETE firewall/policies/{id}."""
    return {
        "name": f"Delete policy: {change.name}",
        "ubiquiti.unifi_api.network": {
            "path": (
                f"{_API_PATH_PREFIX}/sites/{{{{ site_id }}}}/firewall/policies/{change.policy_id}"
            ),
            "method": "DELETE",
        },
    }


def _pf_create_task(change, host: str) -> dict:
    """POST to legacy REST API for port forwarding."""
    return {
        "name": f"Create port forward: {change.name}",
        "ansible.builtin.uri": {
            "url": f"{host}/proxy/network/api/s/default/rest/portforward",
            "method": "POST",
            "headers": {
                "X-API-KEY": "{{ lookup('env', 'UI_API_KEY') }}",
                "Content-Type": "application/json",
            },
            "body_format": "json",
            "body": change.data,
            "validate_certs": False,
            "status_code": [200, 201],
        },
    }


def _pf_update_task(change, host: str) -> dict:
    """PUT to legacy REST API for port forwarding."""
    return {
        "name": f"Update port forward: {change.name}",
        "ansible.builtin.uri": {
            "url": f"{host}/proxy/network/api/s/default/rest/portforward/{change.pfwd_id}",
            "method": "PUT",
            "headers": {
                "X-API-KEY": "{{ lookup('env', 'UI_API_KEY') }}",
                "Content-Type": "application/json",
            },
            "body_format": "json",
            "body": change.data,
            "validate_certs": False,
            "status_code": [200],
        },
    }


def _pf_delete_task(change, host: str) -> dict:
    """DELETE from legacy REST API for port forwarding."""
    return {
        "name": f"Delete port forward: {change.name}",
        "ansible.builtin.uri": {
            "url": f"{host}/proxy/network/api/s/default/rest/portforward/{change.pfwd_id}",
            "method": "DELETE",
            "headers": {
                "X-API-KEY": "{{ lookup('env', 'UI_API_KEY') }}",
            },
            "validate_certs": False,
            "status_code": [200, 204],
        },
    }


def _policy_reorder_task(entry) -> dict:
    """PUT firewall/policies/ordering for a zone pair.

    Uses the module's native query parameter to pass the zone-pair IDs
    as query string params (match_path would reject them in the path).
    """
    return {
        "name": f"Reorder policies: {entry.source_zone} -> {entry.destination_zone}",
        "ubiquiti.unifi_api.network": {
            "path": (
                f"{_API_PATH_PREFIX}/sites/{{{{ site_id }}}}/firewall/policies/ordering"
            ),
            "method": "PUT",
            "query": {
                "sourceFirewallZoneId": entry.source_zone_id,
                "destinationFirewallZoneId": entry.destination_zone_id,
            },
            "body": {
                "orderedFirewallPolicyIds": {
                    "beforeSystemDefined": entry.ordered_policy_ids,
                    "afterSystemDefined": [],
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# Core generator
# ---------------------------------------------------------------------------

def generate_playbook(
    changeset: Changeset,
    site_id: str,
    host: str,
    output_path: str,
    admin_zone_id: str | None = None,
) -> str:
    """Generate an Ansible playbook from a changeset.

    Task ordering (safe by design):
      1. Zone creates          — new zones with empty networkIds
      2. Admin safety policies — "Admin Allow All" creates run before anything else
      3. Zone network updates  — assign networks to zones (new & existing)
      4. Remaining policy creates
      5. Policy updates
      6. Policy deletes        — reverse order (least-permissive first)
      7. Zone deletes          — reverse order
      8. Policy reorder        — or a TODO comment if needs_reorder is True
      9. Port forward changes  — create, update, delete (legacy REST API)

    `admin_zone_id` enables a deterministic Admin-allow-all detection in
    Phase 2; when omitted, no policies are reclassified as Admin-safety
    (they all flow through Phase 4 instead).

    Returns the path to the generated playbook file.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    tasks: list[dict] = []

    # ------------------------------------------------------------------
    # Phase 1: Zone creates
    # ------------------------------------------------------------------
    if changeset.zones_to_create:
        tasks.append({"name": "# Phase 1: Zone creates"})  # comment placeholder
    for change in changeset.zones_to_create:
        tasks.append(_zone_create_task(change))

    # ------------------------------------------------------------------
    # Phase 2: Admin safety policies (creates only)
    # Admin Allow All = source_zone Admin, action ALLOW, no destination ports.
    # These must exist before we start assigning networks or reordering so
    # the Admin zone always has a path back to every zone.
    # ------------------------------------------------------------------
    admin_creates = [
        c for c in changeset.policies_to_create
        if (
            admin_zone_id is not None
            and c.data.get("source", {}).get("zoneId") == admin_zone_id
            and c.data.get("action", {}).get("type") == "ALLOW"
            and not c.data.get("destination", {}).get("trafficFilter")
        )
    ]
    remaining_creates = [
        c for c in changeset.policies_to_create
        if c not in admin_creates
    ]

    if admin_creates:
        tasks.append({"name": "# Phase 2: Admin safety policy creates"})
    for change in admin_creates:
        tasks.append(_policy_create_task(change))

    # ------------------------------------------------------------------
    # Phase 3: Zone network assignment updates
    # ------------------------------------------------------------------
    if changeset.zones_to_update:
        tasks.append({"name": "# Phase 3: Zone network updates"})
    for change in changeset.zones_to_update:
        tasks.append(_zone_update_task(change))

    # ------------------------------------------------------------------
    # Phase 4: Remaining policy creates
    # ------------------------------------------------------------------
    if remaining_creates:
        tasks.append({"name": "# Phase 4: Policy creates"})
    for change in remaining_creates:
        tasks.append(_policy_create_task(change))

    # ------------------------------------------------------------------
    # Phase 5: Policy updates
    # ------------------------------------------------------------------
    if changeset.policies_to_update:
        tasks.append({"name": "# Phase 5: Policy updates"})
    for change in changeset.policies_to_update:
        tasks.append(_policy_update_task(change))

    # ------------------------------------------------------------------
    # Phase 6: Policy deletes — reverse order so we remove the
    # least-permissive (most specific) rules last.
    # ------------------------------------------------------------------
    if changeset.policies_to_delete:
        tasks.append({"name": "# Phase 6: Policy deletes (reverse order)"})
    for change in reversed(changeset.policies_to_delete):
        tasks.append(_policy_delete_task(change))

    # ------------------------------------------------------------------
    # Phase 7: Zone deletes — reverse order
    # ------------------------------------------------------------------
    if changeset.zones_to_delete:
        tasks.append({"name": "# Phase 7: Zone deletes (reverse order)"})
    for change in reversed(changeset.zones_to_delete):
        tasks.append(_zone_delete_task(change))

    # ------------------------------------------------------------------
    # Phase 8: Policy reorder (per zone-pair)
    # ------------------------------------------------------------------
    reorder_ready = [e for e in changeset.reorder_entries if not e.has_pending_creates]
    reorder_pending = [e for e in changeset.reorder_entries if e.has_pending_creates]

    if reorder_ready:
        tasks.append({"name": "# Phase 8: Policy reorder"})
    for entry in reorder_ready:
        tasks.append(_policy_reorder_task(entry))

    if reorder_pending:
        pairs = ", ".join(f"{e.source_zone}->{e.destination_zone}" for e in reorder_pending)
        tasks.append({
            "name": f"Policy reorder deferred — new policies in: {pairs}",
            "ansible.builtin.debug": {
                "msg": (
                    f"Reorder deferred for zone pairs with newly created policies: {pairs}. "
                    "Run reconcile.py plan again after this playbook applies."
                ),
            },
        })

    # ------------------------------------------------------------------
    # Phase 9: Port forward changes (legacy REST API)
    # Uses ansible.builtin.uri instead of ubiquiti.unifi_api.network
    # because port forwarding lives on a different API path.
    # ------------------------------------------------------------------
    has_pf_changes = (
        changeset.pf_to_create or changeset.pf_to_update or changeset.pf_to_delete
    )
    if has_pf_changes:
        tasks.append({"name": "# Phase 9: Port forward changes"})
    for change in changeset.pf_to_create:
        tasks.append(_pf_create_task(change, host))
    for change in changeset.pf_to_update:
        tasks.append(_pf_update_task(change, host))
    for change in reversed(changeset.pf_to_delete):
        tasks.append(_pf_delete_task(change, host))

    # ------------------------------------------------------------------
    # Build the full play
    # ------------------------------------------------------------------
    # Strip bare comment-placeholder tasks — they're not valid Ansible tasks.
    # We used them as section markers above; replace with block_comment via
    # a debug task with a recognisable name prefix.
    real_tasks = []
    for task in tasks:
        if set(task.keys()) == {"name"} and task["name"].startswith("# "):
            # Convert section header to a debug no-op so playbook stays valid
            real_tasks.append({
                "name": f"[section] {task['name'][2:]}",
                "ansible.builtin.debug": {
                    "msg": task["name"][2:],
                },
            })
        else:
            real_tasks.append(task)

    play = {
        "name": f"UDM Pro reconciliation - {timestamp}",
        "hosts": "localhost",
        "gather_facts": False,
        "vars": {
            "site_id": site_id,
        },
        "module_defaults": {
            "group/ubiquiti.unifi_api.common": {
                "base_url": host,
                "token": "{{ lookup('env', 'UI_API_KEY') }}",
                "validate_certs": False,
            },
        },
        "tasks": real_tasks,
    }

    playbook = [play]

    # ------------------------------------------------------------------
    # Write output
    # ------------------------------------------------------------------
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w") as fh:
        fh.write("---\n")
        fh.write(_dump(playbook))

    return output_path
