# nuclei_mcp_server.py — Nuclei MCP Server (Pure ASGI SSE)
# Part of VigilOps v3.0 — Blue Team Intelligence Node
# Exposes nuclei template-based vulnerability scanning via MCP.
# Used by HoneyBadger (pre-siege web recon) and the Orchestrator
# (post-incident CVE validation).
import uvicorn
import subprocess
import json
import re
from mcp.server import Server
from mcp.server.sse import SseServerTransport
import mcp.types as types

app = Server("VigilOps-Nuclei-Node")

# ── CONFIG ─────────────────────────────────────────────────────────
NUCLEI_BIN       = "/usr/local/bin/nuclei"
TEMPLATES_DIR    = "/home/wazuhub/nuclei-templates"
SCAN_TIMEOUT     = 120   # seconds per scan — increase for thorough scans


# ── HELPERS ────────────────────────────────────────────────────────

def _run_nuclei(args: list, timeout: int = SCAN_TIMEOUT) -> str:
    """Run nuclei with given args and return stdout as string."""
    cmd = [NUCLEI_BIN] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout.strip()
        if not output:
            # Check stderr for useful messages
            err = result.stderr.strip()
            if err and "[FTL]" not in err:
                return f"[nuclei] No findings. Stderr: {err[:300]}"
            return "[nuclei] No findings for this scan."
        return output
    except subprocess.TimeoutExpired:
        return f"[!] Nuclei scan timed out after {timeout}s. Try a narrower template set."
    except FileNotFoundError:
        return f"[!] Nuclei binary not found at {NUCLEI_BIN}"
    except Exception as e:
        return f"[!] Nuclei error: {str(e)}"


def _parse_nuclei_output(raw: str) -> str:
    """
    Format raw nuclei output for LLM consumption.
    Nuclei output format: [template-id] [protocol] [severity] url [metadata]
    Converts into a clean structured summary.
    """
    if raw.startswith("[!]") or raw.startswith("[nuclei]"):
        return raw

    lines = raw.strip().split("\n")
    findings = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Parse nuclei line: [template-id] [type] [severity] url ["extra"]
        match = re.match(r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)(.*)', line)
        if match:
            template = match.group(1)
            protocol = match.group(2)
            severity = match.group(3).upper()
            target   = match.group(4)
            extra    = match.group(5).strip().strip('"[]"')
            findings.append(
                f"  [{severity}] {template} ({protocol})\n"
                f"      Target : {target}\n"
                f"      Detail : {extra if extra else 'n/a'}"
            )
        else:
            findings.append(f"  {line}")

    if not findings:
        return "[nuclei] No findings parsed."

    return f"Nuclei scan returned {len(findings)} finding(s):\n\n" + "\n\n".join(findings)


# ── TOOL DEFINITIONS ───────────────────────────────────────────────
@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="nuclei_technology_scan",
            description=(
                "Detect web technologies, server versions, and frameworks running on a target URL. "
                "Uses nuclei's technology detection templates. Fast (~10s). "
                "Use before a siege to identify the tech stack."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL (e.g., 'http://192.168.56.102')"
                    }
                },
                "required": ["target"]
            }
        ),
        types.Tool(
            name="nuclei_vuln_scan",
            description=(
                "Scan a target URL for known CVEs and critical/high severity vulnerabilities "
                "using nuclei's CVE and vulnerability templates. Moderate speed (~60s). "
                "Use after technology detection to find exploitable issues."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL (e.g., 'http://192.168.56.102')"
                    },
                    "severity": {
                        "type": "string",
                        "description": "Comma-separated severity levels: critical,high,medium,low,info",
                        "default": "critical,high,medium"
                    }
                },
                "required": ["target"]
            }
        ),
        types.Tool(
            name="nuclei_full_scan",
            description=(
                "Run a comprehensive nuclei scan across technologies, CVEs, misconfigurations, "
                "exposed panels, and default logins on a target. Slow (~90s) but thorough. "
                "Best used at the start of a siege to build a complete attack surface map."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL (e.g., 'http://192.168.56.102')"
                    }
                },
                "required": ["target"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:

    # ── TECHNOLOGY DETECTION ───────────────────────────────────────
    if name == "nuclei_technology_scan":
        target = arguments.get("target", "").strip()
        if not target:
            return [types.TextContent(type="text", text="[!] No target provided.")]

        args = [
            "-u", target,
            "-t", f"{TEMPLATES_DIR}/http/technologies/",
            "-silent",
            "-no-color"
        ]
        raw    = _run_nuclei(args, timeout=30)
        result = _parse_nuclei_output(raw)
        out    = f"Nuclei Technology Scan: {target}\n\n{result}"
        return [types.TextContent(type="text", text=out)]

    # ── CVE / VULNERABILITY SCAN ───────────────────────────────────
    elif name == "nuclei_vuln_scan":
        target   = arguments.get("target", "").strip()
        severity = arguments.get("severity", "critical,high,medium").strip()
        if not target:
            return [types.TextContent(type="text", text="[!] No target provided.")]

        args = [
            "-u", target,
            "-t", f"{TEMPLATES_DIR}/http/cves/",
            "-t", f"{TEMPLATES_DIR}/http/vulnerabilities/",
            "-severity", severity,
            "-silent",
            "-no-color"
        ]
        raw    = _run_nuclei(args, timeout=90)
        result = _parse_nuclei_output(raw)
        out    = f"Nuclei Vulnerability Scan: {target} (severity: {severity})\n\n{result}"
        return [types.TextContent(type="text", text=out)]

    # ── FULL SCAN ──────────────────────────────────────────────────
    elif name == "nuclei_full_scan":
        target = arguments.get("target", "").strip()
        if not target:
            return [types.TextContent(type="text", text="[!] No target provided.")]

        args = [
            "-u", target,
            "-t", f"{TEMPLATES_DIR}/http/technologies/",
            "-t", f"{TEMPLATES_DIR}/http/cves/",
            "-t", f"{TEMPLATES_DIR}/http/vulnerabilities/",
            "-t", f"{TEMPLATES_DIR}/http/misconfiguration/",
            "-t", f"{TEMPLATES_DIR}/http/exposed-panels/",
            "-t", f"{TEMPLATES_DIR}/http/default-logins/",
            "-severity", "critical,high,medium,low",
            "-silent",
            "-no-color"
        ]
        raw    = _run_nuclei(args, timeout=120)
        result = _parse_nuclei_output(raw)
        out    = f"Nuclei Full Scan: {target}\n\n{result}"
        return [types.TextContent(type="text", text=out)]

    else:
        return [types.TextContent(type="text", text=f"[!] Unknown tool: {name}")]


# ── SSE TRANSPORT (Pure ASGI — same proven pattern) ────────────────
transport = SseServerTransport("/messages")


async def asgi_app(scope, receive, send):
    if scope["type"] == "http":
        path = scope["path"]
        if path == "/sse":
            async with transport.connect_sse(scope, receive, send) as streams:
                await app.run(streams[0], streams[1], app.create_initialization_options())
        elif path == "/messages" and scope["method"] == "POST":
            await transport.handle_post_message(scope, receive, send)
        else:
            await send({"type": "http.response.start", "status": 404})
            await send({"type": "http.response.body",  "body": b"Not Found"})


if __name__ == "__main__":
    print("🛡️ VigilOps Nuclei MCP: Online via Pure ASGI on Port 8004")
    print(f"   [→] Nuclei binary : {NUCLEI_BIN}")
    print(f"   [→] Templates dir : {TEMPLATES_DIR}")
    uvicorn.run(asgi_app, host="0.0.0.0", port=8004)
