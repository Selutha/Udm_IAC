# UDM Pro IaC Reconciler

Declarative firewall management for the UniFi Dream Machine Pro. Maintain
zones and firewall policies in a single YAML file, diff against the live
UDM, and apply changes through generated Ansible playbooks.

Operates like `terraform plan / apply`:

1. You edit `desired.yml`
2. `reconcile.py plan` pulls live state, diffs, generates an Ansible playbook
3. You review the playbook
4. `reconcile.py apply` runs it

Python handles diffing and playbook generation. Ansible (via the official
`ubiquiti.unifi_api` collection) handles execution against the UDM API.

## Prerequisites

- Python 3.12+
- Ansible with the `ubiquiti.unifi_api` collection installed
- A UI API key generated on the UDM Pro (Settings > API)
- A `.env` file in the wrapper directory (parent of the repo) or repo root:
  ```bash
  cp .env.example ../.env   # wrapper layout (preferred)
  # edit ../.env with your API key
  ```

### Install dependencies

```bash
pip install requests pyyaml ansible
ansible-galaxy collection install ubiquiti.unifi_api
```

## Usage

All commands are run from the `src/` directory (the repo root).

```bash
# See what would change (default subcommand)
python reconcile.py plan

# Diff only — no playbook generated
python reconcile.py diff

# Apply the latest generated playbook
python reconcile.py apply

# Dump current UDM state
python reconcile.py pull
```

### Options

| Flag | Description |
|------|-------------|
| `--config PATH` / `-c PATH` | Path to desired state YAML (default: `desired.yml`) |
| `--force` | Proceed despite bulk-deletion safety warnings |

### Workflow

```
 desired.yml ──────────┐
                        ├── reconcile.py plan ──> generated/execution_<ts>.yml
 UDM Pro (live state) ──┘        │
                                 │  review the playbook
                                 v
                        reconcile.py apply ──> ansible-playbook runs it
                                 │
                                 v
                        reconcile.py plan ──> "No changes needed" (convergence)
```

## YAML Schema (`desired.yml`)

### `udm` — controller connection

```yaml
udm:
  host: "https://192.168.0.1"
  site_id: "default"              # auto-discovers the real UUID
```

### `zones` — firewall zones

Each key is a zone name. Only zones listed here are managed; everything
else on the UDM is left untouched.

```yaml
zones:
  Internal:
    system: true                  # SYSTEM_DEFINED — only manage network assignments
    networks: [infrastructure]

  Server:
    networks: [server]            # USER_DEFINED — created if missing

  Rental:
    networks: [Rental]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `system` | bool | `false` | If true, the zone is UniFi-managed. IaC will never create or delete it, only update network assignments. |
| `networks` | list of strings | `[]` | Network names to assign to the zone. Names are resolved to UUIDs at runtime. |

### `policies` — firewall policies

Policies are evaluated in list order. The diff engine assigns each policy
an index computed from its position:

```
index = index_base + (position * index_step)
```

```yaml
policies:
  index_base: 10000
  index_step: 1

  rules:
    - name: "Admin Allow All to Server"
      action: allow               # "allow" or "block"
      source: Admin               # zone name
      destination: Server         # zone name
      protocol: all               # "all", "tcp", "udp", or "tcp_udp"

    - name: "Family Allow Plex"
      action: allow
      source: Family
      destination: Server
      protocol: tcp
      destination_port: "32400"   # comma-separated port numbers
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Policy name (must be unique). Used to match against existing policies. |
| `action` | string | `"allow"` | `"allow"` or `"block"`. |
| `source` | string | required | Source zone name. |
| `destination` | string | required | Destination zone name. |
| `protocol` | string | `"all"` | `"all"` (no filter), `"tcp"`, `"udp"`, or `"tcp_udp"`. |
| `destination_port` | string | — | Comma-separated port numbers (e.g. `"80,443"`). Omit for allow-all. |
| `enabled` | bool | `true` | Whether the policy is active. |
| `allow_return_traffic` | bool | `true` | Create matching return-traffic rule. |

### `port_forwarding` — WAN port forwards

List of DNAT rules forwarding traffic from WAN to internal hosts. Managed
via the legacy REST API (`/api/s/default/rest/portforward`), not the
integration v1 API.

```yaml
port_forwarding:
  - name: "Plex Remote Access"
    protocol: tcp
    wan_port: "32400"
    forward_ip: "192.168.2.3"
    forward_port: "32400"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Rule name (must be unique). Used to match against existing rules. |
| `protocol` | string | `"tcp"` | `"tcp"`, `"udp"`, or `"tcp_udp"`. |
| `wan_port` | string | required | External port. Single (`"443"`) or range (`"8080:8090"`). |
| `forward_ip` | string | required | Internal destination IP address. |
| `forward_port` | string | required | Internal destination port. |
| `enabled` | bool | `true` | Whether the rule is active. |
| `interface` | string | `"wan"` | WAN interface: `"wan"`, `"wan2"`, or `"both"`. |

### `absent` — resources to delete

Explicitly mark resources that should not exist. If present on the UDM,
they are deleted. If already absent, no action is taken.

```yaml
absent:
  zones:
    - "OldTestZone"
  policies:
    - "Old Duplicate Policy"
  port_forwards:
    - "Old Port Forward"
```

System zones cannot be listed here (will error). Only USER_DEFINED
policies and port forwards are matched.

## Safety Checks

The diff engine runs safety checks before generating a playbook:

| Check | Severity | Description |
|-------|----------|-------------|
| Admin zone deletion | ERROR (blocks) | Refuses to delete the Admin zone |
| All Admin allow-all deleted | ERROR (blocks) | Refuses to delete every Admin allow-all policy at once |
| Bulk policy delete (>5) | WARNING | Requires `--force` |
| Bulk zone delete (>2) | WARNING | Requires `--force` |
| System zone in absent | ERROR (blocks) | Cannot delete SYSTEM_DEFINED zones |

## Generated Playbook Phases

The generated Ansible playbook orders operations for safety:

1. **Zone creates** — new zones with empty network assignments
2. **Admin safety policies** — Admin allow-all rules (lockout prevention)
3. **Zone network updates** — assign networks to new and existing zones
4. **Policy creates** — remaining new policies
5. **Policy updates** — changed policies
6. **Policy deletes** — in reverse order
7. **Zone deletes** — in reverse order
8. **Policy reorder** — per zone-pair ordering adjustments

## File Layout

```
udm_iac/                    # Wrapper dir (Claude Code cwd)
  .env                      # API credentials (NOT in repo)
  CLAUDE.md                 # Claude Code project instructions (NOT in repo)
  context/                  # Reference material, notes
  src/                      # Git repo root
    desired.yml             # Source of truth
    reconcile.py            # CLI entry point
    api_client.py           # UDM API v1 client (API-key auth)
    pull_state.py           # Fetch + normalize current state
    diff_engine.py          # Desired vs actual comparison
    generate_playbook.py    # Changeset -> Ansible playbook
    generated/              # Output playbooks (one per plan run)
```

## Limitations

- **Networks are not fully managed.** The reconciler controls zone
  membership (which networks belong to which zone) but does not
  create/modify network DHCP, subnet, or VLAN configuration.
- **Policy reorder with new policies** requires two passes. When new
  policies are created in a zone-pair that also needs reordering, the
  first `apply` creates the policies and the second `plan`/`apply`
  fixes the ordering (newly created policy IDs aren't known until
  after creation).
- **Predefined and derived policies** (SYSTEM_DEFINED, DERIVED) are
  never modified. Only USER_DEFINED policies participate in diffing.
