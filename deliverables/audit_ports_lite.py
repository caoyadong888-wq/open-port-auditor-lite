#!/usr/bin/env python3
"""Lite open-port check: Linux ss text, port and bind scope only.

Reads a capture file. Does not run ss or any other scan. Netstat text, process
names, and scope "specific" belong to the full build. Confirm ss flags in the
man page on the host that produced the capture.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

SS_SKIP = {
    "ESTAB",
    "TIME-WAIT",
    "CLOSE-WAIT",
    "SYN-RECV",
    "SYN-SENT",
    "FIN-WAIT-1",
    "FIN-WAIT-2",
    "CLOSING",
    "LAST-ACK",
}


class CaptureError(Exception):
    pass


def scope_of(address: str) -> str:
    if address in {"0.0.0.0", "::", "*"}:
        return "wildcard"
    if address == "::1":
        return "loopback"
    parts = address.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts) and int(parts[0]) == 127:
        return "loopback"
    return "specific"


def parse_port(token: str) -> int:
    if not token.isdigit():
        raise CaptureError(
            "non-numeric port %s; recapture with ss -n. This lite build has no "
            "service-name table. Check the IANA registry if you need the number."
            % token
        )
    port = int(token)
    if port < 1 or port > 65535:
        raise CaptureError("port out of range: %s" % token)
    return port


def split_endpoint(token: str) -> tuple:
    if token.startswith("[") and "]:" in token:
        host, port_s = token[1:].split("]:", 1)
        return host, parse_port(port_s)
    if token.startswith("*:"):
        return "*", parse_port(token[2:])
    if token.startswith("::1:"):
        return "::1", parse_port(token[4:])
    if token.startswith(":::"):
        return "::", parse_port(token[3:])
    if token.count(":") == 1:
        host, port_s = token.rsplit(":", 1)
        return host, parse_port(port_s)
    raise CaptureError("bad endpoint %s" % token)


def parse_ss(text: str) -> list:
    if "Foreign Address" in text or "PID/Program" in text or "Active Internet" in text:
        raise CaptureError("lite build parses ss text only")
    rows = []
    saw_ss = "Local Address:Port" in text or "\nNetid " in text or text.startswith("Netid")
    for line in text.splitlines():
        if "users:" in line:
            line = line.split("users:", 1)[0]
        parts = line.split()
        if len(parts) < 5 or parts[0] not in {"tcp", "udp"}:
            continue
        saw_ss = True
        state = parts[1].upper()
        if state in SS_SKIP or (parts[0] == "tcp" and state != "LISTEN"):
            continue
        if parts[0] == "udp" and state not in {"UNCONN", "LISTEN"}:
            continue
        if not parts[2].isdigit() or not parts[3].isdigit():
            raise CaptureError("unparsed ss line: %s" % line.strip())
        address, port = split_endpoint(parts[4])
        rows.append(
            {
                "proto": parts[0],
                "address": address,
                "port": port,
                "scope": scope_of(address),
            }
        )
    if not saw_ss:
        raise CaptureError("unrecognized capture; lite build expects ss text")
    return rows


def load_policy(data: dict) -> dict:
    if not isinstance(data, dict) or not isinstance(data.get("name"), str):
        raise CaptureError("policy needs a name string")
    allow = data.get("allow")
    if not isinstance(allow, list):
        raise CaptureError("policy allow must be a list")
    rules = []
    for index, rule in enumerate(allow):
        scope = rule.get("scope")
        if scope == "specific":
            raise CaptureError(
                "lite build does not evaluate scope specific; use loopback or any"
            )
        if scope not in {"loopback", "any"}:
            raise CaptureError("rule %d scope must be loopback or any" % index)
        proto = rule.get("proto")
        port = rule.get("port")
        if proto not in {"tcp", "udp"}:
            raise CaptureError("rule %d proto must be tcp or udp" % index)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise CaptureError("rule %d port must be an integer" % index)
        rules.append({"proto": proto, "port": port, "scope": scope})
    return {"name": data["name"].strip(), "allow": rules}


def judge(listeners: list, policy: dict) -> dict:
    rows = []
    for listener in listeners:
        matched = [
            rule
            for rule in policy["allow"]
            if rule["proto"] == listener["proto"] and rule["port"] == listener["port"]
        ]
        verdict = "OK"
        reason = ""
        detail = ""
        if not matched:
            verdict = "WARN"
            reason = "unexpected"
            detail = "no allow rule for %s/%d" % (listener["proto"], listener["port"])
        else:
            scope_fail = all(
                rule["scope"] == "loopback" and listener["scope"] != "loopback"
                for rule in matched
            )
            if scope_fail:
                verdict = "WARN"
                reason = "scope"
                detail = "listener scope is %s; rule requires loopback" % listener["scope"]
        rows.append(
            {
                "verdict": verdict,
                "proto": listener["proto"],
                "address": listener["address"],
                "port": listener["port"],
                "scope": listener["scope"],
                "reason": reason,
                "detail": detail,
            }
        )
    rows.sort(key=lambda row: (row["port"], row["proto"], row["address"], row["verdict"]))
    warnings = [row for row in rows if row["verdict"] == "WARN"]
    return {
        "status": "WARN" if warnings else "PASS",
        "format": "ss",
        "policy": policy["name"],
        "listener_count": len(rows),
        "warnings": len(warnings),
        "rows": rows,
    }


def endpoint_label(address: str, port: int) -> str:
    shown = "[%s]" % address if ":" in address else address
    return "%s:%d" % (shown, port)


def render_text(result: dict) -> str:
    lines = [
        "STATUS %s" % result["status"],
        "format=%s" % result["format"],
        "policy=%s" % result["policy"],
        "listeners=%d" % result["listener_count"],
        "warnings=%d" % result["warnings"],
    ]
    for row in result["rows"]:
        line = "%s %s %s scope=%s" % (
            row["verdict"],
            row["proto"],
            endpoint_label(row["address"], row["port"]),
            row["scope"],
        )
        if row["verdict"] == "WARN":
            line += " reason=%s detail=%s" % (row["reason"], row["detail"])
        lines.append(line)
    return "\n".join(lines) + "\n"


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="Lite ss capture check.")
    parser.add_argument("--capture", required=True)
    parser.add_argument("--policy", required=True)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 2
    try:
        with open(args.capture, encoding="utf-8") as handle:
            listeners = parse_ss(handle.read())
        with open(args.policy, encoding="utf-8") as handle:
            policy = load_policy(json.load(handle))
        result = judge(listeners, policy)
    except (OSError, CaptureError, json.JSONDecodeError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    sys.stdout.write(render_text(result))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
