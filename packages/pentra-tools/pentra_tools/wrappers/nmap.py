"""Nmap wrapper — port scanning and service detection."""

from __future__ import annotations

import logging
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from pentra_scope import ScopeEnforcer

from pentra_tools.base import AsyncToolWrapper, RateLimiter, ToolResult

log = logging.getLogger(__name__)


@dataclass
class PortInfo:
    host: str
    port: int
    protocol: str
    state: str
    service: str
    version: str | None = None
    banner: str | None = None


@dataclass
class NmapResult:
    hosts: list[PortInfo] = field(default_factory=list)
    host_count: int = 0
    open_port_count: int = 0


class NmapWrapper(AsyncToolWrapper):
    """Runs nmap for port and service discovery."""

    name = "nmap"
    description = "Port scanning and service version detection"
    timeout = 600
    rate_limiter = RateLimiter(max_calls=10, period=60)

    # Default: top 1000 ports, version detection, XML output
    DEFAULT_ARGS = ["-sV", "--top-ports", "1000", "-T4", "--open"]

    def __init__(self, scope_enforcer: ScopeEnforcer) -> None:
        super().__init__(scope_enforcer)

    async def run(  # type: ignore[override]
        self,
        target: str,
        *,
        ports: str | None = None,
        extra_args: list[str] | None = None,
        **kwargs: object,
    ) -> ToolResult:
        # 1. Scope check — ALWAYS first
        self.scope.validate_or_raise(target)

        if self.rate_limiter:
            await self.rate_limiter.acquire()

        cmd = ["nmap", "-oX", "-"]  # XML to stdout
        cmd.extend(self.DEFAULT_ARGS)

        if ports:
            cmd.extend(["-p", ports])

        if extra_args:
            cmd.extend(extra_args)

        cmd.append(target)

        log.info("[nmap] starting scan on %s", target)
        t0 = time.monotonic()
        stdout, stderr, returncode = await self._exec(cmd)
        duration = time.monotonic() - t0

        parsed = self._parse_xml(stdout, target)

        log.info(
            "[nmap] %s: %d open port(s) in %.1fs",
            target, parsed.open_port_count, duration,
        )

        return ToolResult(
            tool=self.name,
            success=returncode == 0,
            data=parsed,
            raw=stdout,
            target=target,
            command=cmd,
            duration_seconds=duration,
            error=stderr.strip() if returncode != 0 else None,
        )

    def _parse_xml(self, raw: str, target: str) -> NmapResult:
        result = NmapResult()
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            log.warning("[nmap] could not parse XML output for %s", target)
            return result

        for host in root.findall("host"):
            addr_el = host.find("address")
            host_addr = addr_el.get("addr", target) if addr_el is not None else target

            result.host_count += 1
            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                service_el = port_el.find("service")
                svc_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                svc_version = (
                    f"{service_el.get('product', '')} {service_el.get('version', '')}".strip()
                    if service_el is not None
                    else None
                )

                port_info = PortInfo(
                    host=host_addr,
                    port=int(port_el.get("portid", 0)),
                    protocol=port_el.get("protocol", "tcp"),
                    state="open",
                    service=svc_name,
                    version=svc_version or None,
                )
                result.hosts.append(port_info)
                result.open_port_count += 1

        return result
