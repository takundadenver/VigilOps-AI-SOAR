# vt_mcp_server.py — VirusTotal MCP Server (Pure ASGI SSE)
# Part of VigilOps v3.0 Blue Team Intelligence Node
import uvicorn
import requests
from mcp.server import Server
from mcp.server.sse import SseServerTransport
import mcp.types as types

app = Server("VigilOps-VirusTotal-Node")

# ── CONFIG ─────────────────────────────────────────────────────
VT_API_KEY  = "key"
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def _vt_get(endpoint: str) -> dict:
    """Generic VT GET request with auth headers."""
    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}
    try:
        res = requests.get(f"{VT_BASE_URL}{endpoint}", headers=headers, timeout=15)
        if res.status_code == 200:
            return res.json()
        elif res.status_code == 404:
            return {"error": "not_found", "detail": "Resource has no VirusTotal record."}
        elif res.status_code == 401:
            return {"error": "unauthorized", "detail": "Invalid API key."}
        elif res.status_code == 429:
            return {"error": "rate_limited", "detail": "VT API quota exceeded."}
        else:
            return {"error": f"http_{res.status_code}", "detail": res.text[:200]}
    except Exception as e:
        return {"error": "connection", "detail": str(e)}


def _format_verdict(stats: dict) -> str:
    """Convert VT's analysis stats into a human-readable verdict."""
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total      = malicious + suspicious + harmless + undetected

    if total == 0:
        return "UNKNOWN (no engines reported)"
    if malicious >= 5:
        verdict = "MALICIOUS"
    elif malicious >= 1 or suspicious >= 3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return f"{verdict} ({malicious} malicious / {suspicious} suspicious / {total} engines)"


# ── TOOL DEFINITIONS ────────────────────────────────────────────
@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="check_ip_reputation",
            description="Query VirusTotal for the reputation of an IPv4 address. Returns malicious/clean verdict, country, ASN, and known associations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IPv4 address (e.g., '8.8.8.8')"}
                },
                "required": ["ip"]
            }
        ),
        types.Tool(
            name="check_file_hash",
            description="Query VirusTotal for malware engine verdicts on a file hash (MD5, SHA1, or SHA256).",
            inputSchema={
                "type": "object",
                "properties": {
                    "hash": {"type": "string", "description": "MD5 / SHA1 / SHA256 hash"}
                },
                "required": ["hash"]
            }
        ),
        types.Tool(
            name="check_domain_reputation",
            description="Query VirusTotal for a domain's reputation, categories, and known malicious associations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Fully qualified domain (e.g., 'example.com')"}
                },
                "required": ["domain"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if VT_API_KEY == "PASTE_YOUR_VT_API_KEY_HERE":
        return [types.TextContent(
            type="text",
            text="[!] VT API key not configured in vt_mcp_server.py"
        )]

    # ── IP REPUTATION ───────────────────────────────────────────
    if name == "check_ip_reputation":
        ip = arguments.get("ip", "").strip()
        if not ip:
            return [types.TextContent(type="text", text="[!] No IP provided.")]

        data = _vt_get(f"/ip_addresses/{ip}")
        if "error" in data:
            return [types.TextContent(
                type="text",
                text=f"[!] VT lookup failed: {data['error']} — {data['detail']}"
            )]

        attr   = data.get("data", {}).get("attributes", {})
        stats  = attr.get("last_analysis_stats", {})
        verdict = _format_verdict(stats)

        out = (
            f"VirusTotal IP Reputation: {ip}\n"
            f"  Verdict       : {verdict}\n"
            f"  Country       : {attr.get('country', 'Unknown')}\n"
            f"  ASN           : {attr.get('asn', 'Unknown')} ({attr.get('as_owner', '')})\n"
            f"  Network       : {attr.get('network', 'Unknown')}\n"
            f"  Reputation    : {attr.get('reputation', 0)}\n"
        )
        return [types.TextContent(type="text", text=out)]

    # ── FILE HASH ──────────────────────────────────────────────
    elif name == "check_file_hash":
        h = arguments.get("hash", "").strip().lower()
        if not h:
            return [types.TextContent(type="text", text="[!] No hash provided.")]

        data = _vt_get(f"/files/{h}")
        if "error" in data:
            return [types.TextContent(
                type="text",
                text=f"[!] VT lookup failed: {data['error']} — {data['detail']}"
            )]

        attr = data.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        verdict = _format_verdict(stats)

        out = (
            f"VirusTotal File Hash: {h}\n"
            f"  Verdict        : {verdict}\n"
            f"  File Name      : {attr.get('meaningful_name', 'Unknown')}\n"
            f"  File Type      : {attr.get('type_description', 'Unknown')}\n"
            f"  Size           : {attr.get('size', 0)} bytes\n"
            f"  First Submitted: {attr.get('first_submission_date', 'n/a')}\n"
        )
        return [types.TextContent(type="text", text=out)]

    # ── DOMAIN REPUTATION ──────────────────────────────────────
    elif name == "check_domain_reputation":
        domain = arguments.get("domain", "").strip()
        if not domain:
            return [types.TextContent(type="text", text="[!] No domain provided.")]

        data = _vt_get(f"/domains/{domain}")
        if "error" in data:
            return [types.TextContent(
                type="text",
                text=f"[!] VT lookup failed: {data['error']} — {data['detail']}"
            )]

        attr = data.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        verdict = _format_verdict(stats)
        categories = ", ".join(attr.get("categories", {}).values()) or "Uncategorized"

        out = (
            f"VirusTotal Domain Reputation: {domain}\n"
            f"  Verdict      : {verdict}\n"
            f"  Categories   : {categories}\n"
            f"  Registrar    : {attr.get('registrar', 'Unknown')}\n"
            f"  Reputation   : {attr.get('reputation', 0)}\n"
        )
        return [types.TextContent(type="text", text=out)]

    else:
        return [types.TextContent(type="text", text=f"[!] Unknown tool: {name}")]


# ── SSE TRANSPORT (Pure ASGI, mirrors Wazuh MCP pattern) ───────
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
    print("🛡️ VigilOps VirusTotal MCP: Online via Pure ASGI on Port 8001")
    print(f"   [→] Querying {VT_BASE_URL}")
    uvicorn.run(asgi_app, host="0.0.0.0", port=8001)
