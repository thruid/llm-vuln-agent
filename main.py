"""Command-line entry point for the llm-vuln-agent.

Examples::

    # Analyze a known asset (offline, deterministic mock LLM).
    python main.py --ip 127.0.0.1 --port 8080 --product "Apache Tomcat" --version 9.0.50

    # Probe first (allowlist-guarded), then analyze.
    python main.py --ip 127.0.0.1 --scan --ports 80 8080

    # Write JSON and Markdown reports.
    python main.py --ip 127.0.0.1 --port 8080 --product "Apache Tomcat" --version 9.0.50 \
        --output-json out.json --output-md out.md
"""

from __future__ import annotations

import argparse
import logging
import sys

from config.loader import Config
from models.asset import Asset
from pipeline.factory import build_system
from pipeline.report import report_to_markdown, write_report
from pipeline.workflow import run_workflow


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="LLM-agent based vulnerability discovery & verification")
    p.add_argument("--ip", required=True, help="target IP (must be within the allowlist)")
    p.add_argument("--port", type=int, default=None, help="target port")
    p.add_argument("--service", default=None, help="known service (e.g. http)")
    p.add_argument("--product", default=None, help="known product (e.g. 'Apache Tomcat')")
    p.add_argument("--vendor", default=None, help="known vendor")
    p.add_argument("--version", default=None, help="known version (e.g. 9.0.50)")
    p.add_argument("--banner", default=None, help="known service banner")
    p.add_argument("--scan", action="store_true", help="probe open ports first")
    p.add_argument("--ports", type=int, nargs="*", default=None, help="ports to scan")
    p.add_argument("--config", default=None, help="path to config.yaml")
    p.add_argument("--cve-dir", default=None, help="directory of vulnerability JSON files")
    p.add_argument("--provider", default=None, help="LLM provider override (mock|openai)")
    p.add_argument("--model", default=None, help="LLM model override (e.g. deepseek-v4-flash)")
    p.add_argument("--base-url", default=None, help="LLM API base URL override (e.g. https://api.deepseek.com)")
    p.add_argument("--output-json", default=None, help="write JSON report to this path")
    p.add_argument("--output-md", default=None, help="write Markdown report to this path")
    p.add_argument("--max-steps", type=int, default=None, help="cap on agent loop iterations")
    return p


def _enrich_by_scan(asset: Asset, system, ports: list[int] | None) -> None:
    res = system.registry.call("port_scan", {"ip": asset.ip, "ports": ports or system.config.get("network.scan_ports", [80, 8080])})
    if not res["success"]:
        print(f"[!] port scan failed: {res['error']}", file=sys.stderr)
        return
    open_ports = res["output"]["open_ports"]
    if not open_ports:
        print("[!] no open ports found", file=sys.stderr)
        return
    first = open_ports[0]
    port = int(first["port"])
    banner = first.get("banner", "")
    asset.port = asset.port or port
    asset.banner = asset.banner or banner or None

    svc = system.registry.call("service_detect", {"port": port, "banner": banner})
    if svc["success"]:
        asset.service = asset.service or svc["output"].get("service")
        asset.product = asset.product or svc["output"].get("product")
    if not asset.version and banner:
        ver = system.registry.call("version_detect", {"banner": banner})
        if ver["success"] and ver["output"].get("found"):
            asset.version = ver["output"]["version"]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    config = Config(args.config)
    if args.provider:
        config._data["llm"]["provider"] = args.provider  # noqa: SLF001 - CLI override
    if args.model:
        config._data["llm"]["model"] = args.model  # noqa: SLF001 - CLI override
    if args.base_url:
        config._data["llm"]["base_url"] = args.base_url  # noqa: SLF001 - CLI override
    logging.basicConfig(level=getattr(logging, str(config.get("logging.level", "INFO")).upper(), logging.INFO))

    system = build_system(config, cve_dir=args.cve_dir)

    asset = Asset(
        ip=args.ip,
        port=args.port,
        service=args.service,
        product=args.product,
        vendor=args.vendor,
        version=args.version,
        banner=args.banner,
    )

    if args.scan:
        _enrich_by_scan(asset, system, args.ports)

    report = run_workflow(asset, system, max_steps=args.max_steps)

    print(report_to_markdown(report))
    if args.output_json:
        write_report(report, args.output_json, "json")
        print(f"[*] JSON report written to {args.output_json}")
    if args.output_md:
        write_report(report, args.output_md, "md")
        print(f"[*] Markdown report written to {args.output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
