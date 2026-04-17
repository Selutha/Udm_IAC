"""Unit tests for generate_playbook admin-creates classification (#5 fix)."""

import yaml

from diff_engine import Changeset, PolicyChange
from generate_playbook import generate_playbook


def _allow_all_create(name, source_zone_id):
    return PolicyChange(
        name=name,
        policy_id=None,
        action="create",
        data={
            "source": {"zoneId": source_zone_id},
            "action": {"type": "ALLOW"},
            "destination": {"zoneId": "DEST"},  # no trafficFilter = allow-all
        },
    )


def _load_playbook(path):
    text = open(path).read()
    return yaml.safe_load(text), text


def _task_index(tasks, substring):
    for i, t in enumerate(tasks):
        if substring in t.get("name", ""):
            return i
    return -1


def test_admin_creates_classified_by_zone_id_not_name(tmp_path):
    """Old code matched by name substring — that misclassified policies whose
    NAMES happened to contain 'admin'+'allow' but whose source zone was elsewhere."""
    cs = Changeset(policies_to_create=[
        # name has "admin" + "allow" but source is a non-admin zone — should NOT be in admin section
        _allow_all_create("Server Allow Admin SSH", source_zone_id="SERVER_ID"),
        # name has neither — but source IS Admin → SHOULD be in admin section
        _allow_all_create("Open House Rule", source_zone_id="ADMIN_ID"),
    ])
    out = tmp_path / "play.yml"
    generate_playbook(cs, site_id="SITE", host="https://h",
                      output_path=str(out), admin_zone_id="ADMIN_ID")
    pb, _ = _load_playbook(out)
    tasks = pb[0]["tasks"]

    phase2 = _task_index(tasks, "Phase 2: Admin safety")
    phase4 = _task_index(tasks, "Phase 4: Policy creates")
    open_house = _task_index(tasks, "Open House Rule")
    server_allow = _task_index(tasks, "Server Allow Admin SSH")

    assert phase2 >= 0, "Phase 2 header missing"
    assert phase4 >= 0, "Phase 4 header missing"
    # Open House (real admin allow-all) goes between phase 2 and phase 4
    assert phase2 < open_house < phase4
    # Server policy (despite name) goes after phase 4 header
    assert server_allow > phase4


def test_no_admin_zone_id_means_no_admin_section(tmp_path):
    """If admin_zone_id is None, no policy is reclassified — all creates go to Phase 4."""
    cs = Changeset(policies_to_create=[
        _allow_all_create("Admin Allow All", source_zone_id="ADMIN_ID"),
    ])
    out = tmp_path / "play.yml"
    generate_playbook(cs, site_id="SITE", host="https://h",
                      output_path=str(out), admin_zone_id=None)
    pb, _ = _load_playbook(out)
    tasks = pb[0]["tasks"]

    assert _task_index(tasks, "Phase 2: Admin safety") == -1
    phase4 = _task_index(tasks, "Phase 4: Policy creates")
    admin_pol = _task_index(tasks, "Admin Allow All")
    assert phase4 >= 0 and admin_pol > phase4


def test_admin_create_with_traffic_filter_not_classified_as_safety(tmp_path):
    """An Admin policy that's port-restricted is not allow-all — keep it out of Phase 2."""
    cs = Changeset(policies_to_create=[
        PolicyChange(
            name="Admin SSH Only",
            policy_id=None,
            action="create",
            data={
                "source": {"zoneId": "ADMIN_ID"},
                "action": {"type": "ALLOW"},
                "destination": {
                    "zoneId": "DEST",
                    "trafficFilter": {"type": "PORT", "portFilter": {"items": [{"value": 22}]}},
                },
            },
        ),
    ])
    out = tmp_path / "play.yml"
    generate_playbook(cs, site_id="SITE", host="https://h",
                      output_path=str(out), admin_zone_id="ADMIN_ID")
    pb, _ = _load_playbook(out)
    tasks = pb[0]["tasks"]
    assert _task_index(tasks, "Phase 2: Admin safety") == -1
    assert _task_index(tasks, "Phase 4: Policy creates") >= 0


def test_admin_block_action_not_classified_as_safety(tmp_path):
    """A block policy from Admin is obviously not a safety rule."""
    cs = Changeset(policies_to_create=[
        PolicyChange(
            name="Admin Block X",
            policy_id=None,
            action="create",
            data={
                "source": {"zoneId": "ADMIN_ID"},
                "action": {"type": "BLOCK"},
                "destination": {"zoneId": "DEST"},
            },
        ),
    ])
    out = tmp_path / "play.yml"
    generate_playbook(cs, site_id="SITE", host="https://h",
                      output_path=str(out), admin_zone_id="ADMIN_ID")
    pb, _ = _load_playbook(out)
    assert _task_index(pb[0]["tasks"], "Phase 2: Admin safety") == -1
