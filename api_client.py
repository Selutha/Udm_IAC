"""UDM Pro v1 Network API client using API-key authentication."""

import functools
import os
import requests
import urllib3

# Suppress insecure HTTPS warnings (self-signed cert on UDM)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_REPO_DIR = os.path.dirname(os.path.abspath(__file__))
_WRAPPER_DIR = os.path.dirname(_REPO_DIR)

# Look for .env in the wrapper dir first (standard layout), then repo root
_DEFAULT_ENV_PATH = (
    os.path.join(_WRAPPER_DIR, ".env")
    if os.path.exists(os.path.join(_WRAPPER_DIR, ".env"))
    else os.path.join(_REPO_DIR, ".env")
)

# Path prefix shared by all integration v1 endpoints
_API_ROOT = "/proxy/network/integration/v1"


def load_env(env_path=None):
    """Load .env file variables into os.environ.

    Defaults to .env in the repo root.
    Only sets variables that are not already present in the environment
    (os.environ.setdefault), so shell exports take precedence.
    """
    if env_path is None:
        env_path = _DEFAULT_ENV_PATH
    env_path = os.path.abspath(env_path)
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    os.environ.setdefault(key.strip(), val.strip())


class UDMApiClient:
    """Thin wrapper around the UDM Pro v1 Network API.

    Authentication is via the X-API-KEY header rather than cookie+CSRF.

    The integration API lives at:

        {host}/proxy/network/integration/v1/sites/{site_id}

    When site_id="default" (the default), the client auto-discovers the
    real UUID by calling the sites list endpoint and matching on
    internalReference == "default".  The discovered UUID is cached so
    only one extra request is made per client instance.

    Pass base_url to override the entire base path (e.g. during testing).
    """

    def __init__(self, host, api_key, site_id="default", base_url=None):
        """
        Args:
            host:     Controller address, e.g. "https://192.168.0.1".
                      Trailing slash is stripped automatically.
            api_key:  Value of the UI_API_KEY environment variable.
            site_id:  UniFi site UUID or "default" to trigger auto-discovery.
            base_url: Override the computed site base URL entirely.
        """
        self._host = host.rstrip("/")
        self._site_id = site_id
        self._base_override = base_url.rstrip("/") if base_url else None

        self._session = requests.Session()
        self._session.verify = False
        self._session.headers.update({
            "X-API-KEY": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        # Default 30s timeout on every request — a hung UDM should fail fast,
        # not block the reconciler indefinitely.
        self._session.request = functools.partial(self._session.request, timeout=30)

    # ------------------------------------------------------------------
    # Site-ID discovery
    # ------------------------------------------------------------------

    def _resolve_site_base(self):
        """Return the base URL for site-scoped endpoints.

        If site_id is "default", fetches the sites list on the first call
        and resolves the UUID whose internalReference is "default".
        """
        if self._base_override:
            return self._base_override

        if self._site_id == "default":
            sites = self.list_sites()
            match = next(
                (s for s in sites if s.get("internalReference") == "default"),
                None,
            )
            if match is None:
                raise RuntimeError(
                    "Could not find a site with internalReference='default'. "
                    "Pass site_id=<uuid> explicitly."
                )
            # Cache the resolved UUID so future calls skip the lookup
            self._site_id = match["id"]

        return f"{self._host}{_API_ROOT}/sites/{self._site_id}"

    @property
    def site_id(self) -> str:
        """Return the resolved site UUID, auto-discovering on first access."""
        self._resolve_site_base()
        return self._site_id

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _root_url(self, path):
        """Build a URL relative to the API root (not site-scoped)."""
        return f"{self._host}{_API_ROOT}/{path.lstrip('/')}"

    def _site_url(self, path):
        """Build a URL relative to the site base."""
        return f"{self._resolve_site_base()}/{path.lstrip('/')}"

    def _get_raw(self, url, params=None):
        """GET a URL and return the parsed JSON body."""
        resp = self._session.get(url, params=params)
        resp.raise_for_status()
        return resp.json() if resp.text else {}

    # Hard cap on pagination: 50 pages * 200 items = 10K items, far more than
    # any UDM list. Protects against a server returning a bad totalCount.
    _MAX_PAGES = 50

    def _paginate(self, url):
        """GET a list endpoint, auto-paginating up to _MAX_PAGES."""
        body = self._get_raw(url, params={"limit": 200})

        if not isinstance(body, dict) or "data" not in body:
            return body

        data = body["data"]
        total = body.get("totalCount", len(data))

        for _ in range(self._MAX_PAGES):
            if len(data) >= total:
                break
            body = self._get_raw(url, params={"limit": 200, "offset": len(data)})
            page = body.get("data", [])
            if not page:
                break
            data.extend(page)
        else:
            raise RuntimeError(
                f"Pagination exceeded {self._MAX_PAGES} pages for {url} "
                f"(got {len(data)} items, totalCount={total})"
            )

        return data

    def _get_site(self, path):
        """GET a site-scoped path, auto-paginating if needed."""
        return self._paginate(self._site_url(path))

    def _get_root(self, path):
        """GET a root-level path (not site-scoped)."""
        return self._paginate(self._root_url(path))

    def _post(self, path, data):
        resp = self._session.post(self._site_url(path), json=data)
        resp.raise_for_status()
        return resp.json() if resp.text else {}

    def _put(self, path, data):
        resp = self._session.put(self._site_url(path), json=data)
        resp.raise_for_status()
        return resp.json() if resp.text else {}

    def _patch(self, path, data):
        resp = self._session.patch(self._site_url(path), json=data)
        resp.raise_for_status()
        return resp.json() if resp.text else {}

    def _delete(self, path):
        resp = self._session.delete(self._site_url(path))
        resp.raise_for_status()
        # DELETE often returns 204 No Content — handle empty body gracefully
        return resp.json() if resp.text else {}

    # ------------------------------------------------------------------
    # Root-level endpoints (not site-scoped)
    # ------------------------------------------------------------------

    def get_info(self) -> dict:
        """Return controller info, e.g. {"applicationVersion": "10.2.105"}."""
        return self._get_root("info")

    def list_sites(self) -> list[dict]:
        """Return all sites.  Each entry has id, internalReference, name."""
        return self._get_root("sites")

    # ------------------------------------------------------------------
    # Firewall zones
    # ------------------------------------------------------------------

    def list_zones(self) -> list[dict]:
        return self._get_site("firewall/zones")

    def create_zone(self, name, network_ids=None) -> dict:
        payload = {"name": name, "networkIds": network_ids or []}
        return self._post("firewall/zones", payload)

    def get_zone(self, zone_id) -> dict:
        return self._get_site(f"firewall/zones/{zone_id}")

    def update_zone(self, zone_id, data) -> dict:
        return self._put(f"firewall/zones/{zone_id}", data)

    def delete_zone(self, zone_id) -> None:
        self._delete(f"firewall/zones/{zone_id}")

    # ------------------------------------------------------------------
    # Firewall policies
    # ------------------------------------------------------------------

    def list_policies(self) -> list[dict]:
        return self._get_site("firewall/policies")

    def create_policy(self, data) -> dict:
        return self._post("firewall/policies", data)

    def get_policy(self, policy_id) -> dict:
        return self._get_site(f"firewall/policies/{policy_id}")

    def update_policy(self, policy_id, data) -> dict:
        return self._put(f"firewall/policies/{policy_id}", data)

    def patch_policy(self, policy_id, data) -> dict:
        return self._patch(f"firewall/policies/{policy_id}", data)

    def delete_policy(self, policy_id) -> None:
        self._delete(f"firewall/policies/{policy_id}")

    def get_policy_ordering(self, source_zone_id, dest_zone_id) -> dict:
        """GET policy ordering for a zone pair.

        Returns {"orderedFirewallPolicyIds": {"beforeSystemDefined": [...], "afterSystemDefined": [...]}}.
        """
        url = self._site_url("firewall/policies/ordering")
        resp = self._session.get(url, params={
            "sourceFirewallZoneId": source_zone_id,
            "destinationFirewallZoneId": dest_zone_id,
        })
        resp.raise_for_status()
        return resp.json()

    def set_policy_ordering(self, source_zone_id, dest_zone_id, ordering) -> dict:
        """PUT policy ordering for a zone pair.

        ordering: {"orderedFirewallPolicyIds": {"beforeSystemDefined": [...], "afterSystemDefined": [...]}}
        """
        url = self._site_url("firewall/policies/ordering")
        resp = self._session.put(url, json=ordering, params={
            "sourceFirewallZoneId": source_zone_id,
            "destinationFirewallZoneId": dest_zone_id,
        })
        resp.raise_for_status()
        return resp.json() if resp.text else {}

    # ------------------------------------------------------------------
    # Networks
    # ------------------------------------------------------------------

    def list_networks(self) -> list[dict]:
        return self._get_site("networks")

    def get_network(self, network_id) -> dict:
        return self._get_site(f"networks/{network_id}")

    def create_network(self, data) -> dict:
        return self._post("networks", data)

    def update_network(self, network_id, data) -> dict:
        return self._put(f"networks/{network_id}", data)

    def delete_network(self, network_id) -> None:
        self._delete(f"networks/{network_id}")

    # ------------------------------------------------------------------
    # Legacy REST API — port forwarding
    # ------------------------------------------------------------------
    # Port forwarding is not exposed on the integration v1 API.  It lives
    # on the older REST API at /proxy/network/api/s/{site}/rest/portforward.
    # The same X-API-KEY header works for auth.  Response format differs:
    #   {"meta": {"rc": "ok"}, "data": [...]}

    def _legacy_url(self, path: str) -> str:
        """Build a URL under the legacy REST API (site = 'default')."""
        return f"{self._host}/proxy/network/api/s/default/rest/{path.lstrip('/')}"

    def _get_legacy(self, path: str) -> list[dict]:
        """GET a legacy REST path and return the data array."""
        url = self._legacy_url(path)
        resp = self._session.get(url)
        resp.raise_for_status()
        body = resp.json() if resp.text else {}
        return body.get("data", [])

    def _post_legacy(self, path: str, data: dict) -> dict:
        url = self._legacy_url(path)
        resp = self._session.post(url, json=data)
        resp.raise_for_status()
        body = resp.json() if resp.text else {}
        items = body.get("data", [])
        return items[0] if items else body

    def _put_legacy(self, path: str, data: dict) -> dict:
        url = self._legacy_url(path)
        resp = self._session.put(url, json=data)
        resp.raise_for_status()
        body = resp.json() if resp.text else {}
        items = body.get("data", [])
        return items[0] if items else body

    def _delete_legacy(self, path: str) -> None:
        url = self._legacy_url(path)
        resp = self._session.delete(url)
        resp.raise_for_status()

    def list_port_forwards(self) -> list[dict]:
        return self._get_legacy("portforward")

    def create_port_forward(self, data: dict) -> dict:
        return self._post_legacy("portforward", data)

    def update_port_forward(self, pfwd_id: str, data: dict) -> dict:
        return self._put_legacy(f"portforward/{pfwd_id}", data)

    def delete_port_forward(self, pfwd_id: str) -> None:
        self._delete_legacy(f"portforward/{pfwd_id}")


# ----------------------------------------------------------------------
# Smoke test — python api_client.py
# ----------------------------------------------------------------------

if __name__ == "__main__":
    load_env()

    host = os.environ.get("UDM_HOST")
    api_key = os.environ.get("UI_API_KEY")
    if not host:
        raise SystemExit("UDM_HOST is not set.")
    if not api_key:
        raise SystemExit("UI_API_KEY is not set.")

    client = UDMApiClient(host=host, api_key=api_key)

    info = client.get_info()
    print(f"Controller version: {info.get('applicationVersion', '?')}")

    sites = client.list_sites()
    print(f"Sites:    {len(sites)}")
    for s in sites:
        print(f"  {s['id']}  internalReference={s.get('internalReference')}  name={s.get('name')}")

    zones = client.list_zones()
    policies = client.list_policies()
    networks = client.list_networks()
    port_forwards = client.list_port_forwards()

    print(f"Zones:    {len(zones)}")
    print(f"Policies: {len(policies)}")
    print(f"Networks: {len(networks)}")
    print(f"Port Fwd: {len(port_forwards)}")
    for pf in port_forwards:
        print(f"  {pf.get('name', '?')}: {pf.get('proto')}/{pf.get('dst_port')} -> {pf.get('fwd')}:{pf.get('fwd_port')}")
