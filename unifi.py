# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Block attackers on a UniFi gateway (UDM, UDM Pro, UCG...) by adding them to an IP group.

LanPulse keeps one address group (default "LanPulse Blocklist") up to date. You create ONE firewall
policy in UniFi that blocks traffic whose source is that group; after that, blocking is one click.

Authentication: a UniFi API key (preferred) or a local admin username/password.
"""
from __future__ import annotations

import http.cookiejar
import json
import ssl
import time
import urllib.error
import urllib.request

PLACEHOLDER = "192.0.2.255"   # documentation address, used only so the group is never empty


class UniFiError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The API key travels in a header; never let a redirect carry it somewhere else."""
    def redirect_request(self, *a, **k):
        return None


class UniFi:
    def __init__(self, cfg: dict, gateway: str | None):
        self.cfg = cfg
        self.host = (cfg.get("host") or gateway or "").strip()
        self.site = cfg.get("site") or "default"
        ctx = ssl.create_default_context()
        if not cfg.get("verify_tls"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect(),
                                                  urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = ""
        self.logged_in = False

    @property
    def configured(self) -> bool:
        return bool(self.host and (self.cfg.get("api_key") or (self.cfg.get("username") and self.cfg.get("password"))))

    def _call(self, method: str, path: str, body=None):
        if not self.host:
            raise UniFiError("No UniFi gateway address set.")
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.cfg.get("api_key"):
            headers["X-API-KEY"] = self.cfg["api_key"]
        else:
            if not self.logged_in:
                self._login()
            if self.csrf:
                headers["X-CSRF-Token"] = self.csrf
        req = urllib.request.Request(f"https://{self.host}{path}", method=method, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with self.opener.open(req, timeout=12) as r:
                tok = r.headers.get("X-Updated-CSRF-Token") or r.headers.get("X-CSRF-Token")
                if tok:
                    self.csrf = tok
                data = json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                self.logged_in = False
                raise UniFiError("UniFi refused the login or API key (HTTP %d). Check the key or account permissions." % e.code)
            raise UniFiError(f"UniFi returned HTTP {e.code} for {path}")
        except urllib.error.URLError as e:
            raise UniFiError(f"Can't reach {self.host}: {e.reason}")
        meta = data.get("meta", {})
        if isinstance(meta, dict) and meta.get("rc") == "error":
            raise UniFiError(f"UniFi error: {meta.get('msg', 'unknown')}")
        return data.get("data", data)

    def topology_data(self) -> dict:
        """Everything the Network tab needs to draw real connections: infrastructure, clients and networks (read-only)."""
        base = f"/proxy/network/api/s/{self.site}"
        out, err = {}, ""
        for key, path in (("devices", "/stat/device"), ("clients", "/stat/sta"), ("networks", "/rest/networkconf")):
            try:
                rows = self._call("GET", base + path)
                out[key] = rows if isinstance(rows, list) else []
            except UniFiError as e:
                out[key] = []
                err = err or str(e)
        if err and not any(out.values()):
            raise UniFiError(err)
        return out

    def _login(self):
        body = json.dumps({"username": self.cfg.get("username"), "password": self.cfg.get("password"),
                           "remember": False}).encode()
        req = urllib.request.Request(f"https://{self.host}/api/auth/login", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=12) as r:
                self.csrf = r.headers.get("X-CSRF-Token", "")
        except urllib.error.HTTPError as e:
            try:
                detail = e.read(2000).decode("utf-8", "replace").lower()
            except Exception:
                detail = ""
            if e.code == 499 or any(w in detail for w in ("mfa", "2fa", "two-factor", "token_required", "verification")):
                raise UniFiError("This account asks for an email or app code (two-step login), which LanPulse can't answer. "
                                 "Create a local-only admin on the UDM (UniFi OS > Admins & Users > Restrict to local access only) "
                                 "or use an API key instead.")
            if e.code in (400, 401, 403):
                raise UniFiError("UniFi rejected the username or password (HTTP %d). Use a local-only admin account, "
                                 "not your UI.com cloud login." % e.code)
            raise UniFiError("UniFi login failed (HTTP %d)." % e.code)
        except urllib.error.URLError as e:
            raise UniFiError(f"Can't reach {self.host}: {e.reason}")
        self.logged_in = True

    # ---- address group
    def _groups(self):
        return self._call("GET", f"/proxy/network/api/s/{self.site}/rest/firewallgroup")

    def _group(self):
        name = self.cfg.get("group") or "LanPulse Blocklist"
        return next((g for g in self._groups() if g.get("name") == name and g.get("group_type") == "address-group"), None)

    def blocked(self) -> list[str]:
        g = self._group()
        return [m for m in (g or {}).get("group_members", []) if m != PLACEHOLDER]

    def block(self, ip: str) -> list[str]:
        g = self._group()
        path = f"/proxy/network/api/s/{self.site}/rest/firewallgroup"
        if not g:
            self._call("POST", path, {"name": self.cfg.get("group") or "LanPulse Blocklist",
                                      "group_type": "address-group", "group_members": [ip]})
            return [ip]
        members = [m for m in g.get("group_members", []) if m != PLACEHOLDER]
        if ip not in members:
            members.append(ip)
            g["group_members"] = members
            self._call("PUT", f"{path}/{g['_id']}", g)
        return members

    def unblock(self, ip: str) -> list[str]:
        g = self._group()
        if not g:
            return []
        members = [m for m in g.get("group_members", []) if m not in (ip, PLACEHOLDER)]
        g["group_members"] = members or [PLACEHOLDER]
        self._call("PUT", f"/proxy/network/api/s/{self.site}/rest/firewallgroup/{g['_id']}", g)
        return members

    def test(self) -> dict:
        t0 = time.time()
        groups = self._groups()
        g = self._group()
        return {"ok": True, "ms": int((time.time() - t0) * 1000), "groups": len(groups),
                "group_exists": bool(g), "blocked": len([m for m in (g or {}).get("group_members", []) if m != PLACEHOLDER])}
