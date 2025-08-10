#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
sigsurgeon — Normalize, convert, and sanity-check Ethereum signatures (offline).

Examples
  # Inspect + normalize + produce compact/standard + badge
  $ python sigsurgeon.py analyze \
      --sig 0x... (65B r||s||v or 64B EIP-2098) \
      --message "Login to Example @ 2025-08-10\nNonce: 12345" \
      --pretty --json report.json --svg badge.svg

  # If you already have a digest (32 bytes hex)
  $ python sigsurgeon.py analyze --sig 0x... --digest 0x... --pretty
"""

import json
import math
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional, Tuple

import click
from eth_utils import keccak, is_hex, to_bytes, to_checksum_address

try:
    from eth_keys.datatypes import Signature
except Exception as e:  # pragma: no cover
    raise SystemExit("eth-keys is required. Install with: pip install eth-keys")

# secp256k1 order (n)
SECPK1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECPK1_HALF_N = SECPK1_N // 2

def strip0x(h: str) -> str:
    return h[2:] if isinstance(h, str) and h.startswith(("0x","0X")) else h

def is_hexlen(h: str, nbytes: int) -> bool:
    s = strip0x(h)
    return is_hex("0x"+s) and len(s) == 2*nbytes

def personal_hash(msg: bytes) -> bytes:
    prefix = f"\x19Ethereum Signed Message:\n{len(msg)}".encode()
    return keccak(prefix + msg)

def parse_sig(sig_hex: str) -> Tuple[int,int,int,bool]:
    """
    Returns (r, s, v27, was_compact)
      - Supports 65B standard (r||s||v) with v in {0,1,27,28,>=35 (EIP-155)}
      - Supports 64B compact (EIP-2098) where vs packs yParity in the top bit of s
    """
    s = strip0x(sig_hex)
    if not is_hex("0x"+s):
        raise click.ClickException("Signature must be hex")
    if len(s) == 130:  # 65B standard
        r = int(s[0:64], 16)
        sv = int(s[64:128], 16)
        v_raw = int(s[128:130], 16)
        if v_raw in (0,1): v_par = v_raw
        elif v_raw in (27,28): v_par = v_raw - 27
        elif v_raw >= 35: v_par = (v_raw - 35) % 2  # EIP-155
        else:
            raise click.ClickException("Invalid v in standard signature")
        v27 = 27 + v_par
        return r, sv, v27, False
    elif len(s) == 128:  # 64B compact (EIP-2098)
        r = int(s[0:64], 16)
        vs = int(s[64:128], 16)
        v_par = (vs >> 255) & 1
        s_val = vs & ((1<<255)-1)
        v27 = 27 + v_par
        return r, s_val, v27, True
    else:
        raise click.ClickException("Signature must be 64 or 65 bytes (hex)")

def to_compact(r: int, s: int, v27: int) -> str:
    v_par = 0 if v27 == 27 else 1
    vs = s | (v_par << 255)
    return "0x" + r.to_bytes(32, "big").hex() + vs.to_bytes(32, "big").hex()

def to_standard(r: int, s: int, v27: int) -> str:
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([v27]).hex()

def low_s_normalize(r: int, s: int, v27: int) -> Tuple[int,int,int,bool]:
    """
    Enforce EIP-2 low-s. If s > n/2, replace s := n - s and flip v parity.
    Returns (r', s', v27', changed)
    """
    if s == 0 or s >= SECPK1_N or r == 0 or r >= SECPK1_N:
        raise click.ClickException("r or s out of range")
    if s <= SECPK1_HALF_N:
        return r, s, v27, False
    new_s = SECPK1_N - s
    new_v27 = 27 if v27 == 28 else 28
    return r, new_s, new_v27, True

def recover_address(msg_hash: bytes, r: int, s: int, v27: int) -> Optional[str]:
    try:
        sig = Signature(vrs=(v27, r, s))
        pub = sig.recover_public_key_from_msg_hash(msg_hash)
        return pub.to_checksum_address()
    except Exception:
        return None

@dataclass
class Finding:
    level: str     # LOW/MEDIUM/HIGH
    kind: str
    message: str
    context: Dict[str, Any]

def score(fs):
    pts = 0
    for f in fs:
        pts += 40 if f.level == "HIGH" else 20 if f.level == "MEDIUM" else 5
    pts = min(100, pts)
    label = "OK" if pts < 30 else "REVIEW" if pts < 70 else "DANGER"
    return pts, label

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """sigsurgeon — Normalize, convert, and sanity-check Ethereum signatures."""
    pass

@cli.command("analyze")
@click.option("--sig", required=True, help="Signature hex (65B r||s||v or 64B EIP-2098 compact).")
@click.option("--message", type=str, default=None, help="Human text to hash with EIP-191 (personal_sign).")
@click.option("--digest", type=str, default=None, help="32-byte message hash (0x...). If set, --message is ignored.")
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON report.")
@click.option("--svg", "svg_out", type=click.Path(writable=True), default=None, help="Write tiny SVG badge.")
@click.option("--pretty", is_flag=True, help="Human-readable output.")
def analyze_cmd(sig, message, digest, json_out, svg_out, pretty):
    """Inspect signature, normalize to low-s, convert formats, and (optionally) recover signer."""
    r, s, v27, was_compact = parse_sig(sig)

    findings = []

    # Low-s normalize
    changed = False
    try:
        r2, s2, v2, changed = low_s_normalize(r, s, v27)
    except click.ClickException as e:
        findings.append(Finding("HIGH", "range", str(e), {}))
        r2, s2, v2 = r, s, v27

    if changed:
        findings.append(Finding("LOW", "low-s", "Signature converted to low-s (EIP-2)", {}))

    # V origin
    v_origin = "parity(27/28)"
    raw_v = int(strip0x(sig)[128:130], 16) if len(strip0x(sig)) == 130 else None
    if raw_v is not None and raw_v >= 35:
        findings.append(Finding("LOW", "eip155", "v looked like EIP-155 (tx-style); parity recovered", {"v_raw": raw_v}))
        v_origin = "eip155->parity"
    elif raw_v in (0,1):
        findings.append(Finding("LOW", "v01", "v was 0/1; normalized to 27/28", {"v_raw": raw_v}))
        v_origin = "0/1->27/28"

    # Build encodings
    std_hex = to_standard(r2, s2, v2)
    cpt_hex = to_compact(r2, s2, v2)

    # Recover (optional)
    addr = None
    used_hash = None
    if digest and is_hexlen(digest, 32):
        used_hash = to_bytes(hexstr=digest)
        addr = recover_address(used_hash, r2, s2, v2)
    elif message is not None:
        used_hash = personal_hash(message.encode("utf-8"))
        addr = recover_address(used_hash, r2, s2, v2)

    if addr is None and (message or digest):
        findings.append(Finding("MEDIUM", "recover", "Signer recovery failed (check message/digest and signature)", {}))

    report = {
        "input": {
            "was_compact": was_compact,
            "v_origin": v_origin
        },
        "normalized": {
            "r": "0x"+r2.to_bytes(32,"big").hex(),
            "s": "0x"+s2.to_bytes(32,"big").hex(),
            "v": v2,
            "standard_hex": std_hex,
            "compact_hex": cpt_hex
        },
        "recovery": {
            "mode": "digest" if digest else ("personal_sign" if message is not None else None),
            "hash": ("0x"+used_hash.hex()) if used_hash else None,
            "address": addr
        },
        "findings": [asdict(f) for f in findings]
    }

    risk_score, risk_label = score(findings)
    report["risk"] = {"score": risk_score, "label": risk_label}

    if pretty:
        click.echo(f"sigsurgeon — risk {risk_score}/100 ({risk_label})")
        click.echo(f"  normalized v: {v2}  low-s: {'yes' if changed else 'already'}")
        click.echo(f"  standard (65B): {std_hex}")
        click.echo(f"  compact  (64B): {cpt_hex}")
        if addr:
            click.echo(f"  recovered: {addr}  (mode: {report['recovery']['mode']})")
        if findings:
            click.echo("  notes:")
            for f in findings:
                click.echo(f"    - {f.level}: {f.kind} — {f.message} {f.context}")

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        click.echo(f"Wrote JSON report: {json_out}")

    if svg_out:
        color = "#3fb950" if risk_label == "OK" else "#d29922" if risk_label == "REVIEW" else "#f85149"
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="780" height="48" role="img" aria-label="sigsurgeon">
  <rect width="780" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    sigsurgeon: {risk_label} — low-s {'OK' if changed or (s <= SECPK1_HALF_N) else 'NO'} — v {v2}
  </text>
  <circle cx="755" cy="24" r="6" fill="{color}"/>
</svg>"""
        with open(svg_out, "w", encoding="utf-8") as f:
            f.write(svg)
        click.echo(f"Wrote SVG badge: {svg_out}")

    if not (pretty or json_out or svg_out):
        click.echo(json.dumps(report, indent=2))

if __name__ == "__main__":
    cli()
