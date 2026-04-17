"""CLI entry point for the UDM Pro IaC reconciler.

Subcommands:
    plan   (default) — pull + diff + safety check + generate playbook + summary
    diff             — pull + diff + safety check + print changeset, no playbook
    apply            — run the latest generated playbook via ansible-playbook
    pull             — print current state summary

Usage:
    python reconcile.py [plan|diff|apply|pull] [--config desired.yml] [--force]
"""

import argparse
import glob
import os
import subprocess
import sys
from datetime import datetime, timezone

from api_client import UDMApiClient, load_env
from diff_engine import Changeset, compute_diff, parse_desired, safety_check
from generate_playbook import generate_playbook
from pull_state import CurrentState, pull_current_state


# ---------------------------------------------------------------------------
# Colour helpers — thin wrappers so we can turn off easily
# ---------------------------------------------------------------------------

_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_RED    = "\033[31m"
_CYAN   = "\033[36m"
_RESET  = "\033[0m"
_BOLD   = "\033[1m"


def _c(colour: str, text: str) -> str:
    """Wrap text in an ANSI colour code (only when stdout is a tty)."""
    if not sys.stdout.isatty():
        return text
    return f"{colour}{text}{_RESET}"


# ---------------------------------------------------------------------------
# Environment / client setup
# ---------------------------------------------------------------------------

def _make_client() -> tuple[UDMApiClient, str, str]:
    """Load env, validate required vars, return (client, host, api_key)."""
    load_env()
    host = os.environ.get("UDM_HOST", "").rstrip("/")
    api_key = os.environ.get("UI_API_KEY", "")
    if not host:
        raise SystemExit("UDM_HOST is not set — check your .env file.")
    if not api_key:
        raise SystemExit("UI_API_KEY is not set — check your .env file.")
    client = UDMApiClient(host=host, api_key=api_key)
    return client, host, api_key


# ---------------------------------------------------------------------------
# Changeset printer (colourised)
# ---------------------------------------------------------------------------

def _print_changeset(cs: Changeset, current: CurrentState | None = None) -> None:
    """Print a colourised diff-style summary of the changeset."""
    if cs.zones_to_create:
        print(f"\nZones to CREATE ({len(cs.zones_to_create)}):")
        for z in cs.zones_to_create:
            nets = z.data.get("networkIds", [])
            print(_c(_GREEN, f"  + {z.name}") + f"  networkIds={nets}")

    if cs.zones_to_update:
        print(f"\nZones to UPDATE ({len(cs.zones_to_update)}):")
        for z in cs.zones_to_update:
            nets = z.data.get("networkIds", [])
            print(_c(_YELLOW, f"  ~ {z.name}") + f"  (id={z.zone_id})  networkIds={nets}")

    if cs.zones_to_delete:
        print(f"\nZones to DELETE ({len(cs.zones_to_delete)}):")
        for z in cs.zones_to_delete:
            print(_c(_RED, f"  - {z.name}") + f"  (id={z.zone_id})")

    if cs.policies_to_create:
        print(f"\nPolicies to CREATE ({len(cs.policies_to_create)}):")
        for p in cs.policies_to_create:
            src_id = p.data.get("source", {}).get("zoneId", "?")
            dst_id = p.data.get("destination", {}).get("zoneId", "?")
            if current:
                src = current.zone_ids_to_names.get(src_id, src_id)
                dst = current.zone_ids_to_names.get(dst_id, dst_id)
            else:
                src, dst = src_id, dst_id
            print(_c(_GREEN, f"  + {p.name}") + f"  ({src} -> {dst})")

    if cs.policies_to_update:
        print(f"\nPolicies to UPDATE ({len(cs.policies_to_update)}):")
        for p in cs.policies_to_update:
            src_id = p.data.get("source", {}).get("zoneId", "?")
            dst_id = p.data.get("destination", {}).get("zoneId", "?")
            if current:
                src = current.zone_ids_to_names.get(src_id, src_id)
                dst = current.zone_ids_to_names.get(dst_id, dst_id)
            else:
                src, dst = src_id, dst_id
            print(_c(_YELLOW, f"  ~ {p.name}") + f"  (id={p.policy_id})  ({src} -> {dst})")

    if cs.policies_to_delete:
        print(f"\nPolicies to DELETE ({len(cs.policies_to_delete)}):")
        for p in cs.policies_to_delete:
            print(_c(_RED, f"  - {p.name}") + f"  (id={p.policy_id})")

    if cs.pf_to_create:
        print(f"\nPort forwards to CREATE ({len(cs.pf_to_create)}):")
        for pf in cs.pf_to_create:
            d = pf.data
            print(_c(_GREEN, f"  + {pf.name}") + f"  {d.get('proto')}/{d.get('dst_port')} -> {d.get('fwd')}:{d.get('fwd_port')}")

    if cs.pf_to_update:
        print(f"\nPort forwards to UPDATE ({len(cs.pf_to_update)}):")
        for pf in cs.pf_to_update:
            d = pf.data
            print(_c(_YELLOW, f"  ~ {pf.name}") + f"  (id={pf.pfwd_id})  {d.get('proto')}/{d.get('dst_port')} -> {d.get('fwd')}:{d.get('fwd_port')}")

    if cs.pf_to_delete:
        print(f"\nPort forwards to DELETE ({len(cs.pf_to_delete)}):")
        for pf in cs.pf_to_delete:
            print(_c(_RED, f"  - {pf.name}") + f"  (id={pf.pfwd_id})")

    if cs.needs_reorder:
        ready = [e for e in cs.reorder_entries if not e.has_pending_creates]
        pending = [e for e in cs.reorder_entries if e.has_pending_creates]
        for e in ready:
            print(
                _c(_CYAN, f"  \u2195 Reorder: {e.source_zone} -> {e.destination_zone}")
                + f"  ({len(e.ordered_policy_ids)} policies)"
            )
        for e in pending:
            print(
                _c(_YELLOW, f"  \u2195 Reorder deferred: {e.source_zone} -> {e.destination_zone}")
                + "  (new policies — rerun plan after apply)"
            )


def _print_change_summary(cs: Changeset) -> None:
    """One-line-per-category totals."""
    lines = []
    if cs.zones_to_create:
        lines.append(_c(_GREEN, f"+{len(cs.zones_to_create)} zone(s)"))
    if cs.zones_to_update:
        lines.append(_c(_YELLOW, f"~{len(cs.zones_to_update)} zone(s)"))
    if cs.zones_to_delete:
        lines.append(_c(_RED, f"-{len(cs.zones_to_delete)} zone(s)"))
    if cs.policies_to_create:
        lines.append(_c(_GREEN, f"+{len(cs.policies_to_create)} policy(s)"))
    if cs.policies_to_update:
        lines.append(_c(_YELLOW, f"~{len(cs.policies_to_update)} policy(s)"))
    if cs.policies_to_delete:
        lines.append(_c(_RED, f"-{len(cs.policies_to_delete)} policy(s)"))
    if cs.pf_to_create:
        lines.append(_c(_GREEN, f"+{len(cs.pf_to_create)} port fwd(s)"))
    if cs.pf_to_update:
        lines.append(_c(_YELLOW, f"~{len(cs.pf_to_update)} port fwd(s)"))
    if cs.pf_to_delete:
        lines.append(_c(_RED, f"-{len(cs.pf_to_delete)} port fwd(s)"))
    if cs.needs_reorder:
        ready = sum(1 for e in cs.reorder_entries if not e.has_pending_creates)
        pending = sum(1 for e in cs.reorder_entries if e.has_pending_creates)
        parts = []
        if ready:
            parts.append(f"{ready} pair(s)")
        if pending:
            parts.append(f"{pending} deferred")
        lines.append(_c(_CYAN, f"\u2195 reorder: {', '.join(parts)}"))
    print("  " + "  ".join(lines))


# ---------------------------------------------------------------------------
# Current-state summary (mirrors pull_state.py __main__)
# ---------------------------------------------------------------------------

def _print_current_state(state: CurrentState) -> None:
    print(f"\nZones ({len(state.zones)}):")
    for name, z in sorted(state.zones.items()):
        tag = " [system]" if z.system else ""
        nets = ", ".join(z.network_names) if z.network_names else "(none)"
        print(f"  {name}{tag}: {nets}")

    user_policies = [p for p in state.policies if p.origin == "USER_DEFINED"]
    print(f"\nUSER_DEFINED policies ({len(user_policies)}):")
    for p in user_policies:
        ports = f"  ports={p.destination_ports}" if p.destination_ports else ""
        print(
            f"  [{p.index}] {p.name}"
            f"\n        {p.source_zone} -> {p.destination_zone}"
            f"  proto={p.protocol}{ports}"
        )

    by_origin: dict[str, int] = {}
    for p in state.policies:
        by_origin[p.origin] = by_origin.get(p.origin, 0) + 1

    print("\nPolicy totals:")
    for origin, count in sorted(by_origin.items()):
        print(f"  {origin}: {count}")
    print(f"  TOTAL: {len(state.policies)}")

    print(f"\nNetworks: {len(state.networks)}")

    print(f"\nPort forwards ({len(state.port_forwards)}):")
    if state.port_forwards:
        for name, pf in sorted(state.port_forwards.items()):
            status = "enabled" if pf.enabled else "disabled"
            print(f"  {pf.name}: {pf.protocol}/{pf.wan_port} -> {pf.forward_ip}:{pf.forward_port}  [{status}]")
    else:
        print("  (none)")


# ---------------------------------------------------------------------------
# ansible-playbook path resolution
# ---------------------------------------------------------------------------

def _find_ansible_playbook() -> str:
    """Return the path to ansible-playbook, preferring the project venv.

    Strategy:
    1. Look for ansible-playbook next to the current Python interpreter
       (handles venvs transparently — if we're already in the right venv,
       this just works).
    2. Fall back to the known relative venv path ../ubi/.venv/bin.
    3. Fall back to whatever is on PATH.
    """
    # Same bin dir as the interpreter running us right now
    python_bin = os.path.dirname(sys.executable)
    candidate = os.path.join(python_bin, "ansible-playbook")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate

    # Relative venv used by this project
    script_dir = os.path.dirname(os.path.abspath(__file__))
    venv_candidate = os.path.join(script_dir, "..", "ubi", ".venv", "bin", "ansible-playbook")
    venv_candidate = os.path.normpath(venv_candidate)
    if os.path.isfile(venv_candidate) and os.access(venv_candidate, os.X_OK):
        return venv_candidate

    # Last resort — whatever is on PATH
    return "ansible-playbook"


def _find_latest_playbook() -> str | None:
    """Return the most recently modified playbook in generated/, or None."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pattern = os.path.join(script_dir, "generated", "execution_*.yml")
    matches = sorted(glob.glob(pattern))
    return matches[-1] if matches else None


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_plan(args) -> int:
    client, host, _ = _make_client()

    print("Pulling current state...")
    current = pull_current_state(client)
    site_id = client.site_id  # resolved UUID (property triggers discovery if needed)

    print(f"Parsing {args.config} ...")
    desired = parse_desired(args.config)

    print("Computing diff...")
    changeset = compute_diff(desired, current)

    issues = safety_check(changeset, desired, current)
    if issues:
        print("\nSafety check:")
        for issue in issues:
            if issue.startswith("ERROR:"):
                print(_c(_RED, f"  {issue}"))
            else:
                print(_c(_YELLOW, f"  {issue}"))
        has_errors = any(i.startswith("ERROR:") for i in issues)
        has_warnings = any(i.startswith("WARNING:") for i in issues)
        if has_errors:
            return 1
        if has_warnings and not args.force:
            print("\nPass --force to proceed despite warnings.")
            return 1

    if changeset.is_empty:
        print(_c(_GREEN, "\nNo changes needed — desired state matches current state."))
        return 0

    print("\nChanges:")
    _print_changeset(changeset, current)

    # Generate playbook
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, "generated", f"execution_{timestamp}.yml")

    playbook_path = generate_playbook(
        changeset, site_id, host, output_path,
        admin_zone_id=current.zone_ids.get("Admin"),
    )
    print(f"\nPlaybook written: {_c(_BOLD, playbook_path)}")
    print("Run `reconcile.py apply` to execute it.")
    return 0


def cmd_diff(args) -> int:
    client, _, _ = _make_client()

    print("Pulling current state...")
    current = pull_current_state(client)

    print(f"Parsing {args.config} ...")
    desired = parse_desired(args.config)

    print("Computing diff...")
    changeset = compute_diff(desired, current)

    issues = safety_check(changeset, desired, current)
    if issues:
        print("\nSafety check:")
        for issue in issues:
            if issue.startswith("ERROR:"):
                print(_c(_RED, f"  {issue}"))
            else:
                print(_c(_YELLOW, f"  {issue}"))
        has_errors = any(i.startswith("ERROR:") for i in issues)
        has_warnings = any(i.startswith("WARNING:") for i in issues)
        if has_errors:
            return 1
        if has_warnings and not args.force:
            print("\nPass --force to proceed despite warnings.")
            return 1

    if changeset.is_empty:
        print(_c(_GREEN, "\nNo changes needed — desired state matches current state."))
        return 0

    _print_changeset(changeset, current)
    return 0


def cmd_apply(args) -> int:
    load_env()  # ensure UI_API_KEY is in env for the ansible subprocess
    playbook = _find_latest_playbook()
    if playbook is None:
        print("No generated playbook found. Run `reconcile.py plan` first.")
        return 1

    ansible = _find_ansible_playbook()
    print(f"Running: {ansible} {playbook}")
    print()

    result = subprocess.run([ansible, playbook])
    return result.returncode


def cmd_pull(args) -> int:
    client, _, _ = _make_client()
    print("Pulling current state...")
    current = pull_current_state(client)
    _print_current_state(current)
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_config = os.path.join(script_dir, "desired.yml")

    parser = argparse.ArgumentParser(
        description="UDM Pro IaC reconciler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
subcommands:
  plan   pull + diff + generate playbook + print summary  (default)
  diff   pull + diff + print changeset (no playbook generated)
  apply  run the latest generated playbook via ansible-playbook
  pull   dump current state summary
        """,
    )

    sub = parser.add_subparsers(dest="command")

    # Shared options for commands that read desired.yml
    def _add_common(p):
        p.add_argument(
            "--config", "-c",
            default=default_config,
            metavar="PATH",
            help="Path to desired.yml (default: desired.yml next to this script)",
        )
        p.add_argument(
            "--force",
            action="store_true",
            help="Proceed despite safety WARNINGs (ERRORs always abort)",
        )

    plan_p = sub.add_parser("plan", help="Pull, diff, and generate playbook (default)")
    _add_common(plan_p)

    diff_p = sub.add_parser("diff", help="Pull and diff; print changeset only")
    _add_common(diff_p)

    sub.add_parser("apply", help="Run the latest generated playbook")

    sub.add_parser("pull", help="Dump current UDM Pro state")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = _build_parser()
    args = parser.parse_args()

    # Default to 'plan' if no subcommand given
    if args.command is None:
        args.command = "plan"
        # plan needs --config and --force attrs; set defaults
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if not hasattr(args, "config"):
            args.config = os.path.join(script_dir, "desired.yml")
        if not hasattr(args, "force"):
            args.force = False

    dispatch = {
        "plan":  cmd_plan,
        "diff":  cmd_diff,
        "apply": cmd_apply,
        "pull":  cmd_pull,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))
