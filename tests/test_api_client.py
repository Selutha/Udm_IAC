"""Unit tests for api_client (timeout, pagination cap, site_id property)."""

import functools
import pytest

from api_client import UDMApiClient


def _client():
    return UDMApiClient(host="https://1.2.3.4", api_key="secret")


# ---------------------------------------------------------------------------
# #2 Timeout
# ---------------------------------------------------------------------------

def test_session_request_carries_default_timeout():
    """Every HTTP call must default to a 30s timeout."""
    c = _client()
    assert isinstance(c._session.request, functools.partial)
    assert c._session.request.keywords.get("timeout") == 30


# ---------------------------------------------------------------------------
# #6 site_id property
# ---------------------------------------------------------------------------

def test_site_id_property_with_base_override_skips_resolution():
    """When base_url is overridden, site_id stays as configured."""
    c = UDMApiClient(host="https://h", api_key="k", base_url="https://override")
    # _resolve_site_base returns the override and doesn't touch _site_id
    assert c.site_id == "default"


def test_site_id_property_resolves_default_via_list_sites(monkeypatch):
    c = _client()
    monkeypatch.setattr(c, "list_sites", lambda: [
        {"id": "REAL-UUID", "internalReference": "default", "name": "Default"},
    ])
    assert c.site_id == "REAL-UUID"
    # Cached: a second access should NOT call list_sites again
    monkeypatch.setattr(c, "list_sites", lambda: pytest.fail("cache miss"))
    assert c.site_id == "REAL-UUID"


def test_site_id_property_raises_when_no_default_site(monkeypatch):
    c = _client()
    monkeypatch.setattr(c, "list_sites", lambda: [
        {"id": "X", "internalReference": "other", "name": "Other"},
    ])
    with pytest.raises(RuntimeError, match="internalReference='default'"):
        _ = c.site_id


# ---------------------------------------------------------------------------
# #3 Pagination hard cap
# ---------------------------------------------------------------------------

def test_pagination_hard_cap_raises(monkeypatch):
    """A server with bad totalCount must not loop forever."""
    c = _client()
    c._base_override = "https://1.2.3.4/sites/default"  # skip resolution

    calls = {"n": 0}

    def fake_get_raw(url, params=None):
        calls["n"] += 1
        return {
            "data": [{"id": f"x-{calls['n']}-{i}"} for i in range(200)],
            "totalCount": 99999,
        }

    monkeypatch.setattr(c, "_get_raw", fake_get_raw)

    with pytest.raises(RuntimeError, match="Pagination exceeded"):
        c._get_site("firewall/zones")

    # 1 initial call + 50 loop iterations = 51 total
    assert calls["n"] == 51


def test_pagination_terminates_on_empty_page(monkeypatch):
    """If the server returns an empty page mid-stream, stop without erroring."""
    c = _client()
    c._base_override = "https://1.2.3.4/sites/default"

    pages = [
        {"data": [{"id": f"a{i}"} for i in range(200)], "totalCount": 500},
        {"data": [{"id": f"b{i}"} for i in range(200)]},  # 400 / 500
        {"data": []},  # empty → stop
    ]
    it = iter(pages)
    monkeypatch.setattr(c, "_get_raw", lambda url, params=None: next(it))

    result = c._get_site("firewall/zones")
    assert len(result) == 400


def test_pagination_terminates_when_totalcount_reached(monkeypatch):
    c = _client()
    c._base_override = "https://1.2.3.4/sites/default"

    pages = [
        {"data": [{"id": f"a{i}"} for i in range(200)], "totalCount": 350},
        {"data": [{"id": f"b{i}"} for i in range(150)]},
    ]
    it = iter(pages)
    monkeypatch.setattr(c, "_get_raw", lambda url, params=None: next(it))

    result = c._get_site("firewall/zones")
    assert len(result) == 350


def test_pagination_returns_body_when_not_a_list(monkeypatch):
    """Single-resource GETs return a non-`data` dict; pass through unchanged."""
    c = _client()
    c._base_override = "https://1.2.3.4/sites/default"
    monkeypatch.setattr(c, "_get_raw", lambda url, params=None: {"id": "abc", "name": "Z"})
    result = c._get_site("firewall/zones/abc")
    assert result == {"id": "abc", "name": "Z"}
