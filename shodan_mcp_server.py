# shodan_mcp_server.py — Shodan MCP Server (Pure ASGI SSE)
# Part of VigilOps v3.0 — serves both Blue Team (audit enrichment)
# and Red Team (pre-engagement recon).
import uvicorn
import requests
from mcp.server import Server
from mcp.server.sse import SseServerTransport
import mcp.types as types

app = Server("VigilOps-Shodan-Node")

# ── CONFIG ─────────────────────────────────────────────────────
SHODAN_API_KEY = "key"
SHODAN_BASE    = "https://api.shodan.io"


def _shodan_get(endpoint: str, params: dict = None) -> dict:
    """Generic Shodan GET with API key auth."""
    params = params or {}
    params["key"] = SHODAN_API_KEY
    try:
        res = requests.get(f"{SHODAN_BASE}{endpoint}", params=params, timeout=15)
        if res.status_code == 200:
            return res.json()
        elif res.status_code == 401:
            return {"error": "unauthorized", "detail": "Invalid Shodan API key."}
        elif res.status_code == 404:
            return {"error": "not_found", "detail": "Resource has no Shodan record."}
        elif res.status_code == 429:
            return {"error": "rate_limited", "detail": "Shodan API quota exceeded."}
        else:
            return {"error": f"http_{res.status_code}", "detail": res.text[:200]}
    except Exception as e:
        return {"error": "connection", "detail": str(e)}


# ── TOOL DEFINITIONS ────────────────────────────────────────────
@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="host_lookup",
            description="Look up a public IP in Shodan. Returns open ports, service banners, geolocation, ISP, and OS detection. Use for both red-team pre-engagement recon and blue-team exposure analysis.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IPv4 address (e.g., '8.8.8.8')"}
                },
                "required": ["ip"]
            }
        ),
        types.Tool(
            name="port_search",
            description="Search Shodan for hosts running a specific service or product. Returns up to 10 matching hosts. Useful for finding internet-exposed instances of a vulnerable software version.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Shodan search query (e.g., 'apache 2.4.7', 'port:21 proftpd 1.3.5', 'mongodb -authentication')"}
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="vuln_search",
            description="Search Shodan for hosts with a specific CVE. Returns affected hosts and service banners. Use to identify lateral pivot targets or measure CVE prevalence.",
            inputSchema={
                "type": "object",
                "properties": {
                    "cve": {"type": "string", "description": "CVE identifier (e.g., 'CVE-2014-0226')"}
                },
                "required": ["cve"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if SHODAN_API_KEY == "nbwTmDksePeLvp4S4MFzqs6kf93NHcT7":
        return [types.TextContent(
            type="text",
            text="[!] Shodan API key not configured in shodan_mcp_server.py"
        )]

    # ── HOST LOOKUP ─────────────────────────────────────────────
    if name == "host_lookup":
        ip = arguments.get("ip", "").strip()
        if not ip:
            return [types.TextContent(type="text", text="[!] No IP provided.")]

        data = _shodan_get(f"/shodan/host/{ip}", {"minify": "true"})

        if "error" in data:
            return [types.TextContent(
                type="text",
                text=f"Shodan host_lookup({ip}): {data['error']} — {data['detail']}"
            )]

        ports     = data.get("ports", [])
        hostnames = data.get("hostnames", [])
        org       = data.get("org", "Unknown")
        isp       = data.get("isp", "Unknown")
        country   = data.get("country_name", "Unknown")
        city      = data.get("city", "Unknown")
        os_guess  = data.get("os") or "Unknown"
        vulns     = data.get("vulns", [])

        # Build service banners summary
        services = []
        for item in data.get("data", [])[:8]:
            port    = item.get("port", "?")
            product = item.get("product", "")
            version = item.get("version", "")
            banner  = (item.get("data", "")[:120] or "").replace("\n", " ").strip()
            services.append(f"   - port {port}: {product} {version} | {banner}")

        out = (
            f"Shodan Host Lookup: {ip}\n"
            f"  Location   : {city}, {country}\n"
            f"  Org / ISP  : {org} / {isp}\n"
            f"  OS Guess   : {os_guess}\n"
            f"  Open Ports : {ports}\n"
            f"  Hostnames  : {hostnames}\n"
            f"  Known CVEs : {sorted(list(vulns))[:10] if vulns else 'None reported'}\n"
            f"  Services   :\n" + ("\n".join(services) if services else "   - (no banner data)")
        )
        return [types.TextContent(type="text", text=out)]

    # ── PORT / PRODUCT SEARCH ──────────────────────────────────
    elif name == "port_search":
        query = arguments.get("query", "").strip()
        if not query:
            return [types.TextContent(type="text", text="[!] No query provided.")]

        data = _shodan_get("/shodan/host/search", {"query": query, "limit": 10})

        if "error" in data:
            return [types.TextContent(
                type="text",
                text=f"Shodan port_search('{query}'): {data['error']} — {data['detail']}"
            )]

        total = data.get("total", 0)
        matches = data.get("matches", [])[:10]

        out = f"Shodan Port/Product Search: {query}\n"
        out += f"  Global hits: {total:,} exposed hosts\n\n"

        if not matches:
            out += "  No matching hosts returned (free tier may limit results)."
        else:
            for m in matches:
                ip_addr = m.get("ip_str", "?")
                port    = m.get("port", "?")
                product = m.get("product", "")
                version = m.get("version", "")
                org     = m.get("org", "")
                country = m.get("location", {}).get("country_name", "")
                out += f"   - {ip_addr}:{port} | {product} {version} | {org} ({country})\n"

        return [types.TextContent(type="text", text=out)]

    # ── VULN / CVE SEARCH ──────────────────────────────────────
    elif name == "vuln_search":
        cve = arguments.get("cve", "").strip().upper()
        if not cve:
            return [types.TextContent(type="text", text="[!] No CVE provided.")]

        data = _shodan_get("/shodan/host/search", {"query": f"vuln:{cve}", "limit": 10})

        if "error" in data:
            return [types.TextContent(
                type="text",
                text=f"Shodan vuln_search({cve}): {data['error']} — {data['detail']}\n"
                     f"Note: vuln: filter requires a Shodan Membership ($49/yr) or higher."
            )]

        total = data.get("total", 0)
        matches = data.get("matches", [])[:10]

        out = f"Shodan CVE Exposure Search: {cve}\n"
        out += f"  Vulnerable hosts indexed: {total:,}\n\n"

        if not matches:
            out += "  No matching hosts returned."
        else:
            for m in matches:
                ip_addr = m.get("ip_str", "?")
                port    = m.get("port", "?")
                product = m.get("product", "")
                country = m.get("location", {}).get("country_name", "")
                out += f"   - {ip_addr}:{port} | {product} | {country}\n"

        return [types.TextContent(type="text", text=out)]

    else:
        return [types.TextContent(type="text", text=f"[!] Unknown tool: {name}")]


# ── SSE TRANSPORT ──────────────────────────────────────────────
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
    print("🛡️ VigilOps Shodan MCP: Online via Pure ASGI on Port 8002")
    print(f"   [→] Querying {SHODAN_BASE}")
    uvicorn.run(asgi_app, host="0.0.0.0", port=8002)
