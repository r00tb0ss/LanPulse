# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 The LanPulse authors
"""
Extra context for the IP info box, built only from data LanPulse already holds:

  * did any of YOUR devices connect out to this address (an attacker that is also a destination is a red flag),
  * what the honeypot saw it do (sessions, fingerprints, files, campaign links, the latest session in order),
  * other addresses in the same /24 that also hit you,
  * a plain-English read of how it behaves: background scanning or focused on something of yours.

The read is a pattern in observed traffic, never proof of intent, and it says what it was based on.
"""
from __future__ import annotations

import ipaddress
import logging
import time

log = logging.getLogger("lanpulse.ipcontext")

# Labels grouped by what they mean for you.
BACKGROUND, FOCUSED, DECOY, UNKNOWN = "background", "focused", "decoy", "unknown"


def classify_source(f: dict) -> dict:
    """How does this source behave? `f` holds counts taken from the attack log and honeypot (see facts_from_rows).
    Returns {label, category, level (ignore/watch/act), confidence, evidence[], note}."""
    n = int(f.get("count") or 0)
    ports, targets, repeat = int(f.get("ports") or 0), int(f.get("targets") or 0), int(f.get("max_repeat") or 0)
    days, reached, on_open = int(f.get("days") or 0), int(f.get("reached") or 0), int(f.get("hits_on_open") or 0)
    ev = []

    def out(label, category, level, confidence, why):
        return {"label": label, "category": category, "level": level, "confidence": confidence,
                "evidence": why or ev, "note": "A pattern in the traffic LanPulse saw, not proof of what the sender intended."}

    # Real-service exposure must outrank scanner reputation and decoy activity.
    if reached and on_open:
        return out("Reached a real service", FOCUSED, "act", "high",
                   [f"{reached} attempt{'s' if reached != 1 else ''} were allowed through the router.",
                    f"{on_open} of them matched a port known to be open on one of your devices.",
                    "Investigate the destination device and its service logs."])
    if f.get("tag") or f.get("gn_class") == "benign":
        who = f.get("tag") or "a known benign scanner"
        return out("Research scanner", BACKGROUND, "watch" if reached else "ignore", "high",
                   [f"Identified as {who}.",
                    "Scanner reputation is context, not proof that every connection is harmless."])
    logged_in = bool(f.get("pot_logged_in"))
    commands = int(f.get("pot_commands") or 0)
    if logged_in or commands:
        evidence = ["Successfully logged in to the honeypot."] if logged_in else []
        if commands:
            evidence.append(f"Ran {commands} command{'s' if commands != 1 else ''} in the honeypot.")
        evidence.append("The recorded interactive activity was against a decoy; it does not establish access to a real device.")
        return out("Interactive honeypot activity", DECOY, "watch", "high" if logged_in else "moderate", evidence)
    if repeat >= 5 or (days >= 3 and ports <= 3 and n >= 6):
        why = []
        if repeat >= 5:
            why.append(f"The same target and port was tried {repeat} times.")
        if days >= 3:
            why.append(f"Active on {days} different days.")
        why.append("Repeated, narrow attempts look more like persistence than a one-time sweep.")
        return out("Persistent", FOCUSED, "watch", "moderate", why)
    if ports >= 5 and repeat <= 2 and days <= 2:
        return out("Mass scanning", BACKGROUND, "ignore", "moderate",
                   [f"Tried {ports} different ports, at most {repeat or 1} time{'s' if repeat > 1 else ''} each.",
                    "Spread across many ports, the way internet-wide scans work."])
    if targets >= 3 and ports <= 2 and repeat <= 2:
        return out("Sweeping for one service", BACKGROUND, "ignore", "moderate",
                   [f"Tried {targets} of your addresses on only {ports or 1} port{'s' if ports > 1 else ''}.",
                    "One service across many hosts is the pattern of a sweep, not a chosen target."])
    if n <= 3:
        return out("One-off probe", BACKGROUND, "ignore", "low", [f"Only {n} attempt{'s' if n != 1 else ''} seen."])
    return out("No clear pattern", UNKNOWN, "watch", "low",
               [f"{n} attempts across {ports} port{'s' if ports != 1 else ''} and {days or 1} day{'s' if days > 1 else ''}.",
                "Not enough to call it background scanning or focused activity."])


def facts_from_rows(rows, devices_by_ip: dict, tag: str = "", gn_class: str = "", pot: dict | None = None) -> dict:
    """Counts for classify_source from attack-log rows (t, dport, proto, action, lan, service, sensor, detail)."""
    ports, repeat, targets, day_set, reached, on_open = set(), {}, set(), set(), 0, 0
    for t, dport, _proto, action, lan, *_ in rows:
        ports.add(dport)
        day_set.add(int(t // 86400))
        if lan:
            targets.add(lan)
            repeat[(lan, dport)] = repeat.get((lan, dport), 0) + 1
        if action == "allowed":
            reached += 1
            dev = devices_by_ip.get(lan) or {}
            if any(p.get("port") == dport for p in dev.get("ports", [])):
                on_open += 1
    return {"count": len(rows), "ports": len(ports), "targets": len(targets), "days": len(day_set),
            "max_repeat": max(repeat.values(), default=0), "reached": reached, "hits_on_open": on_open,
            "tag": tag, "gn_class": gn_class, "pot_commands": int((pot or {}).get("commands") or 0),
            "pot_logged_in": bool((pot or {}).get("logged_in") or (pot or {}).get("successful_logins"))}


def neighbours(db, lock, ip: str, days: int = 30, limit: int = 8) -> list[dict]:
    """Other addresses in the same /24 that also attacked, so a whole block can be spotted at a glance."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if addr.version != 4:
        return []
    prefix = ".".join(ip.split(".")[:3]) + "."
    with lock:
        rows = db.execute("SELECT src, COUNT(*), MAX(t) FROM attacks WHERE src LIKE ? AND src != ? AND t > ? "
                          "GROUP BY src ORDER BY COUNT(*) DESC LIMIT ?",
                          (prefix + "%", ip, time.time() - days * 86400, limit)).fetchall()
    return [{"ip": s, "count": c, "last": l} for s, c, l in rows]


def build(nm, ip: str, rows, tag: str = "", gn_class: str = "") -> dict:
    """The extra context block. Every part is optional: a part that fails is left out, never fatal."""
    ctx: dict = {}
    by_ip = {d["ip"]: d for d in list(nm.devices.values())}
    pot = None
    try:
        hp = getattr(nm, "honeyan", None)
        pot = hp.ip_activity(ip) if hp else None
        if pot:
            ctx["honeypot"] = pot
    except Exception:
        log.debug("honeypot context skipped", exc_info=True)
    try:
        fl = getattr(nm, "flows", None)
        if fl:
            ctx["outbound"] = fl.to_dest(ip)
    except Exception:
        log.debug("outbound context skipped", exc_info=True)
    try:
        near = neighbours(nm.threats.db, nm.threats.lock, ip)
        if near:
            ctx["neighbours"] = near
    except Exception:
        log.debug("neighbour context skipped", exc_info=True)
    try:
        ctx["behaviour"] = classify_source(facts_from_rows(rows, by_ip, tag, gn_class, pot))
    except Exception:
        log.debug("behaviour read skipped", exc_info=True)
    return ctx
