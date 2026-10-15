#!/usr/bin/env python3

import argparse
import ipaddress
import json
import math
import re
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


VERSION = "0.2.0"
PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
PEM_END = "-----END CERTIFICATE-----"


@dataclass
class VerifyPaths:
    cafile: Optional[str]
    capath: Optional[str]
    openssl_cafile_env: Optional[str]
    openssl_cafile: Optional[str]
    openssl_capath_env: Optional[str]
    openssl_capath: Optional[str]


@dataclass
class BundleInfo:
    path: Optional[str]
    exists: bool
    size: int
    pem_begin: int
    pem_end: int
    valid_pem_blocks: int = 0
    invalid_pem_blocks: int = 0
    warning: Optional[str] = None


@dataclass
class CAStoreInfo:
    loaded_certificates: int
    sample_subjects: list[Any]
    error: Optional[str] = None


@dataclass
class TLSProbeResult:
    host: str
    port: int
    success: bool
    error: Optional[str]
    tls_version: Optional[str]
    cipher: Optional[Any]
    subject: Optional[Any]
    issuer: Optional[Any]
    not_before: Optional[str]
    not_after: Optional[str]
    days_remaining: Optional[int] = None
    expiration_status: Optional[str] = None
    error_type: Optional[str] = None
    subject_name: Optional[str] = None
    issuer_name: Optional[str] = None


@dataclass
class TLSReport:
    timestamp: float
    verify_paths: VerifyPaths
    bundle: BundleInfo
    ca_store: CAStoreInfo
    probes: list[TLSProbeResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    version: str = VERSION


def get_verify_paths() -> VerifyPaths:
    p = ssl.get_default_verify_paths()
    return VerifyPaths(
        cafile=p.cafile,
        capath=p.capath,
        openssl_cafile_env=p.openssl_cafile_env,
        openssl_cafile=p.openssl_cafile,
        openssl_capath_env=p.openssl_capath_env,
        openssl_capath=p.openssl_capath,
    )


def inspect_bundle(path: Optional[str]) -> BundleInfo:
    if not path:
        return BundleInfo(None, False, 0, 0, 0, warning="No CA bundle file selected")
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        return BundleInfo(path, p.exists(), 0, 0, 0, warning=f"Unable to read bundle: {exc}")
    begin = data.count(PEM_BEGIN.encode("ascii"))
    end = data.count(PEM_END.encode("ascii"))
    pattern = re.compile(rb"-----BEGIN CERTIFICATE-----\s*.*?\s*-----END CERTIFICATE-----", re.DOTALL)
    valid = 0
    invalid = 0
    for match in pattern.finditer(data):
        try:
            ssl.PEM_cert_to_DER_cert(match.group().decode("ascii"))
            valid += 1
        except (ValueError, UnicodeError):
            invalid += 1
    unmatched = max(begin, end) - len(pattern.findall(data))
    warning_parts = []
    if begin != end:
        warning_parts.append("Mismatched certificate PEM markers")
    if unmatched:
        warning_parts.append(f"{unmatched} unmatched PEM marker(s)")
    if invalid:
        warning_parts.append(f"{invalid} invalid certificate PEM block(s)")
    if not begin:
        warning_parts.append("No certificate PEM blocks found")
    return BundleInfo(path, True, len(data), begin, end, valid, invalid, "; ".join(warning_parts) or None)


def create_context(cafile: Optional[str], capath: Optional[str]) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=cafile, capath=capath)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def inspect_ca_store(ctx: ssl.SSLContext) -> CAStoreInfo:
    try:
        certs = ctx.get_ca_certs()
        return CAStoreInfo(len(certs), [c.get("subject") for c in certs[:10]])
    except (ssl.SSLError, OSError, ValueError) as exc:
        return CAStoreInfo(0, [], str(exc))


def format_name(name: Any) -> Optional[str]:
    if not name:
        return None
    pieces = []
    for rdn in name:
        for pair in rdn:
            if len(pair) == 2:
                pieces.append(f"{pair[0]}={pair[1]}")
    return ", ".join(pieces) or None


def parse_cert_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), timezone.utc)
    except (ValueError, OverflowError):
        return None


def classify_expiration(not_before: Optional[str], not_after: Optional[str], threshold: int) -> tuple[Optional[int], str]:
    now = datetime.now(timezone.utc)
    start = parse_cert_time(not_before)
    end = parse_cert_time(not_after)
    if end is None:
        return None, "unknown"
    days = math.floor((end - now).total_seconds() / 86400)
    if start is not None and now < start:
        return days, "not_yet_valid"
    if now > end:
        return days, "expired"
    if (end - now).total_seconds() <= threshold * 86400:
        return days, "expiring_soon"
    return days, "valid"


def probe_host(host: str, port: int, ctx: Optional[ssl.SSLContext], timeout: float, threshold: int, context_error: Optional[str] = None) -> TLSProbeResult:
    base = dict(host=host, port=port, success=False, error=None, tls_version=None, cipher=None, subject=None, issuer=None, not_before=None, not_after=None)
    if ctx is None:
        return TLSProbeResult(**{**base, "error": context_error or "TLS context unavailable", "error_type": "ca_store_error"})
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                days, status = classify_expiration(cert.get("notBefore"), cert.get("notAfter"), threshold)
                return TLSProbeResult(
                    host=host,
                    port=port,
                    success=True,
                    error=None,
                    tls_version=tls_sock.version(),
                    cipher=tls_sock.cipher(),
                    subject=cert.get("subject"),
                    issuer=cert.get("issuer"),
                    not_before=cert.get("notBefore"),
                    not_after=cert.get("notAfter"),
                    days_remaining=days,
                    expiration_status=status,
                    subject_name=format_name(cert.get("subject")),
                    issuer_name=format_name(cert.get("issuer")),
                )
    except ssl.SSLCertVerificationError as exc:
        kind = "certificate_verification_failed"
        message = f"Certificate verification failed: {exc}"
    except ssl.SSLError as exc:
        kind = "tls_error"
        message = f"TLS handshake failed: {exc}"
    except socket.gaierror as exc:
        kind = "dns_error"
        message = f"DNS resolution failed: {exc}"
    except (socket.timeout, TimeoutError) as exc:
        kind = "timeout"
        message = f"Connection timed out: {exc}"
    except ConnectionRefusedError as exc:
        kind = "connection_refused"
        message = f"Connection refused: {exc}"
    except OSError as exc:
        kind = "network_error"
        message = f"Network error: {exc}"
    return TLSProbeResult(**{**base, "error": message, "error_type": kind})


def parse_target(value: str, default_port: int) -> tuple[str, int]:
    value = value.strip()
    if not value:
        raise ValueError("Empty host")
    if value.startswith("["):
        closing = value.find("]")
        if closing == -1:
            raise ValueError(f"Invalid IPv6 target: {value}")
        host = value[1:closing]
        rest = value[closing + 1:]
        if rest and not rest.startswith(":"):
            raise ValueError(f"Invalid target: {value}")
        port = int(rest[1:]) if rest else default_port
    elif value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        port = int(port_text)
    elif ":" in value:
        try:
            ipaddress.IPv6Address(value)
        except ValueError as exc:
            raise ValueError(f"Invalid IPv6 target: {value}") from exc
        host, port = value, default_port
    else:
        host, port = value, default_port
    if not host or not 1 <= port <= 65535:
        raise ValueError(f"Invalid target or port: {value}")
    return host, port


def build_report(hosts: list[str], port: int, cafile: Optional[str], capath: Optional[str], timeout: float, threshold: int) -> TLSReport:
    paths = get_verify_paths()
    bundle = inspect_bundle(cafile or paths.cafile)
    warnings = []
    if bundle.warning:
        warnings.append(bundle.warning)
    ctx = None
    context_error = None
    try:
        ctx = create_context(cafile, capath)
        store = inspect_ca_store(ctx)
    except (ssl.SSLError, OSError, ValueError) as exc:
        context_error = str(exc)
        store = CAStoreInfo(0, [], context_error)
    if store.error:
        warnings.append(f"CA store: {store.error}")
    report = TLSReport(time.time(), paths, bundle, store, warnings=warnings)
    for value in hosts:
        host, target_port = parse_target(value, port)
        result = probe_host(host, target_port, ctx, timeout, threshold, context_error)
        report.probes.append(result)
        if result.expiration_status in ("expired", "expiring_soon", "not_yet_valid"):
            report.warnings.append(f"{host}:{target_port}: certificate {result.expiration_status}")
    return report


def print_text(report: TLSReport) -> None:
    stamp = datetime.fromtimestamp(report.timestamp, timezone.utc).isoformat(timespec="seconds")
    print(f"CA Inspector v{report.version}")
    print(f"Timestamp: {stamp}")
    print()
    print("VERIFY PATHS")
    print(f"  CA file: {report.verify_paths.cafile or '-'}")
    print(f"  CA directory: {report.verify_paths.capath or '-'}")
    print()
    b = report.bundle
    print("CA BUNDLE")
    print(f"  Path: {b.path or '-'}")
    print(f"  Exists: {b.exists}")
    print(f"  Size: {b.size} bytes")
    print(f"  PEM markers: {b.pem_begin} begin, {b.pem_end} end")
    print(f"  Parsed PEM blocks: {b.valid_pem_blocks} valid, {b.invalid_pem_blocks} invalid")
    print()
    print("CA STORE")
    print(f"  Loaded certificates: {report.ca_store.loaded_certificates}")
    if report.ca_store.error:
        print(f"  Error: {report.ca_store.error}")
    print()
    print("TLS PROBES")
    if not report.probes:
        print("  No targets supplied")
    for p in report.probes:
        print(f"  {p.host}:{p.port}  {'OK' if p.success else 'FAILED'}")
        if p.success:
            print(f"    Protocol: {p.tls_version or '-'}")
            print(f"    Cipher: {p.cipher[0] if p.cipher else '-'}")
            print(f"    Subject: {p.subject_name or '-'}")
            print(f"    Issuer: {p.issuer_name or '-'}")
            print(f"    Valid from: {p.not_before or '-'}")
            print(f"    Valid until: {p.not_after or '-'}")
            print(f"    Expiration: {p.expiration_status or '-'} ({p.days_remaining} whole days remaining)")
        else:
            print(f"    Error type: {p.error_type or '-'}")
            print(f"    Error: {p.error or '-'}")
    if report.warnings:
        print()
        print("WARNINGS")
        for warning in report.warnings:
            print(f"  {warning}")


def main() -> int:
    parser = argparse.ArgumentParser(description="TLS CA diagnostics tool")
    parser.add_argument("--host", action="append", help="Host, host:port, IPv6, or [IPv6]:port")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--cafile")
    parser.add_argument("--capath")
    parser.add_argument("--warn-days", type=int, default=30)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a finite positive number")
    if args.warn_days < 0:
        parser.error("--warn-days must be nonnegative")
    try:
        report = build_report(args.host or [], args.port, args.cafile, args.capath, args.timeout, args.warn_days)
    except ValueError as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(asdict(report), indent=2, ensure_ascii=False))
    else:
        print_text(report)
    return 0 if all(p.success for p in report.probes) and not report.ca_store.error else 1


if __name__ == "__main__":
    raise SystemExit(main())
