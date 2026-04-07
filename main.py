#!/usr/bin/env python3

import argparse
import json
import socket
import ssl
import sys
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, List, Optional


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


@dataclass
class CAStoreInfo:
    loaded_certificates: int
    sample_subjects: List[Any]


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


@dataclass
class TLSReport:
    timestamp: float
    verify_paths: VerifyPaths
    bundle: BundleInfo
    ca_store: CAStoreInfo
    probes: List[TLSProbeResult] = field(default_factory=list)


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
        return BundleInfo(path=None, exists=False, size=0, pem_begin=0, pem_end=0)

    p = Path(path)
    if not p.exists():
        return BundleInfo(path=path, exists=False, size=0, pem_begin=0, pem_end=0)

    try:
        data = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return BundleInfo(path=path, exists=True, size=p.stat().st_size, pem_begin=0, pem_end=0)

    return BundleInfo(
        path=path,
        exists=True,
        size=p.stat().st_size,
        pem_begin=data.count("-----BEGIN CERTIFICATE-----"),
        pem_end=data.count("-----END CERTIFICATE-----"),
    )


def inspect_ca_store(cafile: Optional[str], capath: Optional[str]) -> CAStoreInfo:
    ctx = ssl.create_default_context(cafile=cafile, capath=capath)
    certs = ctx.get_ca_certs()
    sample = certs[:10]
    subjects = [c.get("subject") for c in sample]
    return CAStoreInfo(
        loaded_certificates=len(certs),
        sample_subjects=subjects,
    )


def probe_host(host: str, port: int, cafile: Optional[str], capath: Optional[str], timeout: float) -> TLSProbeResult:
    ctx = ssl.create_default_context(cafile=cafile, capath=capath)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
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
                )
    except Exception as exc:
        return TLSProbeResult(
            host=host,
            port=port,
            success=False,
            error=str(exc),
            tls_version=None,
            cipher=None,
            subject=None,
            issuer=None,
            not_before=None,
            not_after=None,
        )


def build_report(
    hosts: List[str],
    port: int,
    cafile: Optional[str],
    capath: Optional[str],
    timeout: float
) -> TLSReport:
    paths = get_verify_paths()
    bundle = inspect_bundle(cafile or paths.cafile)
    store = inspect_ca_store(cafile, capath)

    report = TLSReport(
        timestamp=time.time(),
        verify_paths=paths,
        bundle=bundle,
        ca_store=store,
    )

    for host in hosts:
        result = probe_host(host, port, cafile, capath, timeout)
        report.probes.append(result)

    return report


def print_text(report: TLSReport) -> None:
    print("TLS DIAGNOSTIC REPORT")
    print("=====================")
    print(f"timestamp: {report.timestamp}")
    print()

    vp = report.verify_paths
    print("VERIFY PATHS")
    print("------------")
    print(f"cafile: {vp.cafile}")
    print(f"capath: {vp.capath}")
    print()

    b = report.bundle
    print("BUNDLE")
    print("------")
    print(f"path: {b.path}")
    print(f"exists: {b.exists}")
    print(f"size: {b.size}")
    print(f"pem_begin: {b.pem_begin}")
    print(f"pem_end: {b.pem_end}")
    print()

    s = report.ca_store
    print("CA STORE")
    print("--------")
    print(f"loaded_certificates: {s.loaded_certificates}")
    print()

    print("PROBES")
    print("------")
    for p in report.probes:
        print(f"{p.host}:{p.port} success={p.success}")
        if p.success:
            print(f"  tls={p.tls_version} cipher={p.cipher}")
            print(f"  issuer={p.issuer}")
        else:
            print(f"  error={p.error}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="TLS CA diagnostics tool")
    parser.add_argument("--host", action="append", help="Host to probe")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--cafile")
    parser.add_argument("--capath")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    hosts = args.host or []

    report = build_report(
        hosts=hosts,
        port=args.port,
        cafile=args.cafile,
        capath=args.capath,
        timeout=args.timeout,
    )

    if args.json:
        print(json.dumps(asdict(report), indent=2, ensure_ascii=False))
    else:
        print_text(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
