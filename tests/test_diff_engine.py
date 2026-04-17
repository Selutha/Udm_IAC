"""Unit tests for diff_engine.safety_check and pull_state default-matching."""

from diff_engine import (
    Changeset,
    DesiredPolicy,
    DesiredState,
    PolicyChange,
    ZoneChange,
    safety_check,
)
from pull_state import CurrentState, PolicyState, ZoneState, _normalize_policy


def _current(admin_zone_id="ADMIN_ID", admin_allow_all_names=()):
    policies = [
        PolicyState(
            name=name, id=f"pid-{name}", action="allow",
            source_zone="Admin", destination_zone="Server",
            protocol="all", destination_ports=[],
            enabled=True, allow_return_traffic=True,
            index=10000 + i, origin="USER_DEFINED",
        )
        for i, name in enumerate(admin_allow_all_names)
    ]
    return CurrentState(
        zones={"Admin": ZoneState(name="Admin", id=admin_zone_id, network_names=[], system=False)},
        policies=policies,
        port_forwards={},
        networks={},
        zone_ids={"Admin": admin_zone_id},
        network_ids_to_names={},
        zone_ids_to_names={admin_zone_id: "Admin"},
    )


def _empty_desired():
    return DesiredState(zones={}, policies=[], port_forwards={}, index_base=10000, index_step=1)


# ---------------------------------------------------------------------------
# Lockout check (#1 fix) — regression cases
# ---------------------------------------------------------------------------

def test_lockout_detected_when_desired_has_no_admin_allow_all_but_current_does():
    """Bug fix: previous safety_check missed this — current admin allow-all
    that aren't in desired get implicitly deleted, leaving Admin stranded."""
    current = _current(admin_allow_all_names=["Admin Allow All"])
    cs = Changeset(policies_to_delete=[
        PolicyChange(name="Admin Allow All", policy_id="pid-Admin Allow All",
                     action="delete", data={}),
    ])
    issues = safety_check(cs, _empty_desired(), current)
    errors = [i for i in issues if i.startswith("ERROR:")]
    assert any("Admin allow-all" in e for e in errors), errors


def test_lockout_detected_when_all_admin_allow_all_in_absent():
    """Original case: desired lists policies but they're all in absent."""
    current = _current(admin_allow_all_names=["Admin Allow All"])
    desired = DesiredState(
        zones={},
        policies=[
            DesiredPolicy(name="Admin Allow All", action="allow",
                          source_zone="Admin", destination_zone="Server",
                          protocol="all", destination_ports=[]),
        ],
        port_forwards={}, index_base=10000, index_step=1,
        absent_policies=["Admin Allow All"],
    )
    cs = Changeset(policies_to_delete=[
        PolicyChange(name="Admin Allow All", policy_id="pid-Admin Allow All",
                     action="delete", data={}),
    ])
    issues = safety_check(cs, desired, current)
    assert any("Admin allow-all" in i for i in issues if i.startswith("ERROR:"))


def test_no_lockout_when_replacement_admin_allow_all_being_created():
    """Deleting the old one is OK if a new admin allow-all is being created."""
    current = _current(admin_allow_all_names=["Admin Allow All Old"])
    cs = Changeset(
        policies_to_create=[
            PolicyChange(name="Admin Allow All New", policy_id=None, action="create",
                         data={
                             "source": {"zoneId": "ADMIN_ID"},
                             "action": {"type": "ALLOW"},
                             "destination": {"zoneId": "OTHER"},  # no trafficFilter
                         }),
        ],
        policies_to_delete=[
            PolicyChange(name="Admin Allow All Old", policy_id="pid-x", action="delete", data={}),
        ],
    )
    issues = safety_check(cs, _empty_desired(), current)
    lockouts = [i for i in issues if "Admin allow-all" in i and i.startswith("ERROR:")]
    assert lockouts == []


def test_no_lockout_when_admin_allow_all_unchanged():
    current = _current(admin_allow_all_names=["Admin Allow All"])
    issues = safety_check(Changeset(), _empty_desired(), current)
    assert not any("Admin allow-all" in i for i in issues)


def test_no_lockout_when_current_has_no_admin_allow_all():
    """If there was no protection to begin with, no error."""
    current = _current(admin_allow_all_names=())
    issues = safety_check(Changeset(), _empty_desired(), current)
    assert not any("Admin allow-all" in i for i in issues)


def test_admin_zone_delete_still_blocked():
    """Existing safety-rule sanity check."""
    current = _current()
    cs = Changeset(zones_to_delete=[
        ZoneChange(name="Admin", zone_id="ADMIN_ID", action="delete", data={}),
    ])
    issues = safety_check(cs, _empty_desired(), current)
    assert any("Admin zone is in the delete list" in i for i in issues)


def test_safety_check_back_compat_without_current():
    """Optional `current` arg — call must not raise when omitted."""
    issues = safety_check(Changeset(), _empty_desired())
    assert issues == []  # nothing to flag without current state


# ---------------------------------------------------------------------------
# Default mismatch (#4 fix)
# ---------------------------------------------------------------------------

def test_pulled_policy_defaults_allow_return_traffic_true():
    """Pulled policies missing `allowReturnTraffic` must default True to match
    DesiredPolicy's default — otherwise every plan flags a phantom update."""
    raw = {
        "name": "X", "id": "1",
        "action": {"type": "ALLOW"},  # no allowReturnTraffic key
        "source": {"zoneId": "z1"},
        "destination": {"zoneId": "z2"},
        "ipProtocolScope": {},
        "metadata": {"origin": "USER_DEFINED"},
        "enabled": True, "index": 0,
    }
    pulled = _normalize_policy(raw, {"z1": "A", "z2": "B"})
    desired_default = DesiredPolicy(
        name="X", action="allow", source_zone="A", destination_zone="B",
        protocol="all", destination_ports=[],
    ).allow_return_traffic
    assert pulled.allow_return_traffic == desired_default
