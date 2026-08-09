"""
Proxy configuration + command-line parsing.

The proxy is launched by an MCP host (Claude Desktop, Kiro) as if it *were* the
target server. Its own flags configure interception; everything after a literal
``--`` is the real server command it must spawn and wrap. Example:

    python -m src.proxy.mcp_proxy --name filesystem --trust external \\
        -- npx -y @modelcontextprotocol/server-filesystem C:\\demo

Everything before ``--`` (``--name``, ``--trust`, ...) tunes the firewall;
everything after ``--`` (``npx -y ...``) is the child server, passed through
untouched to ``asyncio.create_subprocess_exec``.
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field


# trigger_source values the engine's SOURCE_TRUST table understands
# (src/pipeline/config.py). --trust maps onto these.
_TRUST_CHOICES = {
    "internal": "internal",
    "external": "external_dm",
    "external_dm": "external_dm",
    "unknown": "unknown",
}

DEFAULT_ENGINE_URL = os.getenv("OMAR_PIPELINE_URL", "http://localhost:8001")

# Keep the hold ceiling at/under the MCP host's own tools/call client timeout
# (Claude Desktop is ~60s) so the host doesn't cancel the call before a human
# resolves it. See plan risk register.
DEFAULT_HOLD_TIMEOUT = float(os.getenv("FIREWALL_HOLD_TIMEOUT", "55"))


@dataclass
class ProxyConfig:
    """Resolved runtime configuration for one wrapped server."""

    name: str                       # logical server name -> agent_id in requests
    command: str                    # child executable (e.g. "npx")
    args: list[str] = field(default_factory=list)   # child args
    trust: str = "internal"         # resolved trigger_source default
    engine_url: str = DEFAULT_ENGINE_URL
    hold_timeout: float = DEFAULT_HOLD_TIMEOUT
    session_id: str = ""            # shared across co-wrapped servers; see config_helper
    workspace_id: str = "default"

    def __post_init__(self) -> None:
        if not self.session_id:
            # Prefer the shared id injected by config_helper so two co-wrapped
            # servers correlate; fall back to a per-launch uuid.
            self.session_id = os.getenv("FIREWALL_SESSION_ID") or f"sess_{uuid.uuid4().hex[:12]}"


class ArgError(ValueError):
    """Raised on malformed CLI args so the caller can print usage and exit 2."""


def parse_args(argv: list[str]) -> ProxyConfig:
    """
    Split argv on the first literal ``--``: firewall flags before it, the child
    server command after it. Deliberately hand-rolled (not argparse) because the
    child command must be captured verbatim, including flags that would otherwise
    collide with the proxy's own (``-y``, ``--port``, ...).
    """
    if "--" not in argv:
        raise ArgError("missing '--' separator: <proxy flags> -- <server command> [args...]")

    sep = argv.index("--")
    flags, child = argv[:sep], argv[sep + 1:]
    if not child:
        raise ArgError("no server command after '--'")

    name = ""
    trust = "internal"
    engine_url = DEFAULT_ENGINE_URL
    hold_timeout = DEFAULT_HOLD_TIMEOUT
    session_id = ""
    workspace_id = "default"

    i = 0
    while i < len(flags):
        flag = flags[i]
        if flag in ("--name", "--trust", "--engine-url", "--hold-timeout",
                    "--session-id", "--workspace-id"):
            if i + 1 >= len(flags):
                raise ArgError(f"{flag} expects a value")
            value = flags[i + 1]
            i += 2
            if flag == "--name":
                name = value
            elif flag == "--trust":
                if value not in _TRUST_CHOICES:
                    raise ArgError(f"--trust must be one of {sorted(_TRUST_CHOICES)}")
                trust = _TRUST_CHOICES[value]
            elif flag == "--engine-url":
                engine_url = value
            elif flag == "--hold-timeout":
                try:
                    hold_timeout = float(value)
                except ValueError as exc:
                    raise ArgError("--hold-timeout must be a number") from exc
            elif flag == "--session-id":
                session_id = value
            elif flag == "--workspace-id":
                workspace_id = value
        else:
            raise ArgError(f"unknown flag: {flag}")

    if not name:
        name = child[0]  # fall back to the executable name

    return ProxyConfig(
        name=name,
        command=child[0],
        args=child[1:],
        trust=trust,
        engine_url=engine_url,
        hold_timeout=hold_timeout,
        session_id=session_id,
        workspace_id=workspace_id,
    )
