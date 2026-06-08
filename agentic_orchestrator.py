import chromadb
from chromadb.utils import embedding_functions
import requests
import json
import os
import re
import asyncio
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession
import codex_engineer
from pcap_hunter import hunt_anomalies

# ---------------------------------------------------------
# VIGILOPS V3: AGENTIC ORCHESTRATOR (Penta-Brain Intelligence)
# Five MCP intelligence sources:
#   1. Wazuh  — live SIEM telemetry
#   2. VT     — IP reputation
#   3. Shodan — host exposure
#   4. Exploit Intel — Exploit-DB + Vulners CVE lookup
#   5. Nuclei — template-based web vulnerability scan
# ---------------------------------------------------------

DB_PATH = "vigil_chroma_db_v3"
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_EMBED_URL = "http://localhost:11434/api/embeddings"
EMBEDDING_MODEL = "nomic-embed-text"
LLM_MODEL = "vigilops-14b"

# Blue Team Intelligence Node ───────────────────────────────
WAZUH_MCP_URL         = "http://192.168.56.104:8000/sse"
VT_MCP_URL            = "http://192.168.56.104:8001/sse"
SHODAN_MCP_URL        = "http://192.168.56.104:8002/sse"
EXPLOIT_INTEL_MCP_URL = "http://192.168.56.104:8003/sse"
NUCLEI_MCP_URL        = "http://192.168.56.104:8004/sse"

# Web target for nuclei
NUCLEI_INFRA_TARGET  = "http://192.168.56.102"
NUCLEI_GENAI_TARGET  = "http://192.168.56.105:5000"


# ==============================================================
#  RAG QUERY
# ==============================================================

def query_database(collection_name, query_text):
    try:
        client = chromadb.PersistentClient(path=DB_PATH)
        ollama_ef = embedding_functions.OllamaEmbeddingFunction(
            url=OLLAMA_EMBED_URL, model_name=EMBEDDING_MODEL
        )
        collection = client.get_collection(name=collection_name, embedding_function=ollama_ef)
        results = collection.query(query_texts=[query_text], n_results=1)
        if results['documents'] and results['documents'][0]:
            return results['documents'][0][0]
        return "No data found."
    except Exception as e:
        return f"Database Error: {e}"


# ==============================================================
#  MCP CLIENT HELPERS
# ==============================================================

async def fetch_mcp_telemetry():
    print(f"   [🔗] Connecting to Wazuh MCP Server at {WAZUH_MCP_URL}...")
    try:
        async with sse_client(WAZUH_MCP_URL) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                print("   [📥] Executing MCP Tool: fetch_critical_alerts...")
                result = await session.call_tool("fetch_critical_alerts", {"limit": 10})
                return result.content[0].text
    except Exception as e:
        print(f"   [!] Wazuh MCP Failed: {e}")
        return None


async def enrich_ip_via_vt(ip: str) -> str:
    try:
        async with sse_client(VT_MCP_URL) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                result = await session.call_tool("check_ip_reputation", {"ip": ip})
                return "\n".join(b.text for b in result.content if hasattr(b, "text"))
    except Exception as e:
        return f"[!] VT lookup failed for {ip}: {e}"


async def enrich_ip_via_shodan(ip: str) -> str:
    try:
        async with sse_client(SHODAN_MCP_URL) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                result = await session.call_tool("host_lookup", {"ip": ip})
                return "\n".join(b.text for b in result.content if hasattr(b, "text"))
    except Exception as e:
        return f"[!] Shodan lookup failed for {ip}: {e}"


async def enrich_service_via_exploitdb(query: str) -> str:
    try:
        async with sse_client(EXPLOIT_INTEL_MCP_URL) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                result = await session.call_tool("searchsploit_lookup", {"query": query})
                return "\n".join(b.text for b in result.content if hasattr(b, "text"))
    except Exception as e:
        return f"[!] Exploit-DB failed for '{query}': {e}"


async def enrich_service_via_vulners(query: str) -> str:
    try:
        async with sse_client(EXPLOIT_INTEL_MCP_URL) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                result = await session.call_tool("vulners_lookup", {"query": query})
                return "\n".join(b.text for b in result.content if hasattr(b, "text"))
    except Exception as e:
        return f"[!] Vulners failed for '{query}': {e}"


async def scan_via_nuclei(target_url: str) -> str:
    try:
        async with sse_client(NUCLEI_MCP_URL) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                result = await session.call_tool("nuclei_full_scan", {"target": target_url})
                return "\n".join(b.text for b in result.content if hasattr(b, "text"))
    except Exception as e:
        return f"[!] Nuclei scan failed for '{target_url}': {e}"


# ==============================================================
#  HELPERS
# ==============================================================

def is_enrichable(ip: str) -> bool:
    octets = ip.split(".")
    if len(octets) != 4:
        return False
    try:
        first = int(octets[0]);
        second = int(octets[1])
    except ValueError:
        return False
    if first == 10: return False
    if first == 127: return False
    if first == 169 and second == 254: return False
    if first == 172 and 16 <= second <= 31: return False
    if first == 192 and second == 168: return False
    if first >= 224: return False
    if ip in ("0.0.0.0", "255.255.255.255"): return False
    return True


def extract_service_signatures(text: str) -> list:
    signatures = set()
    pattern = r"\b(ProFTPD|OpenSSH|Samba|Apache|Tomcat|Jenkins|nginx|MySQL|PostgreSQL|Drupal|WordPress|vsftpd|ProFTPd)\s+([\d]+\.[\d]+(?:\.[\d]+)?)"
    for m in re.finditer(pattern, text, re.IGNORECASE):
        signatures.add(f"{m.group(1)} {m.group(2)}")
    return list(signatures)


def has_web_signals(text: str) -> bool:
    web_keywords = [
        "apache", "http", "tomcat", "drupal", "wordpress",
        "jenkins", "nginx", "web", "html", "php", "jetty"
    ]
    return any(k in text.lower() for k in web_keywords)


# ==============================================================
#  MAIN AUDIT FLOW (Natively Async)
# ==============================================================

async def run_agentic_audit():
    print("🧠 VIGILOPS ORCHESTRATOR: Waking up...")

    # ── PHASE 1: Wazuh telemetry ─────────────────────────────────
    print("   [📥] Fetching Live SIEM Telemetry...")
    pcap_present = os.path.exists("siege_exhaust.pcap")
    mcp_logs = ""

    print("   [🔗] Engaging Wazuh MCP Server for live alert telemetry...")
    fetched = await fetch_mcp_telemetry()
    if fetched:
        mcp_logs = fetched

    print(f"\n[🔍 DEBUG] MCP returned {len(mcp_logs)} chars:\n{mcp_logs[:500]}\n")

    # ── PHASE 2: IP enrichment via VT + Shodan (CONCURRENT) ──────
    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    candidate_ips = set(re.findall(ipv4_pattern, mcp_logs))
    routable_ips = [ip for ip in candidate_ips if is_enrichable(ip)]

    vt_block = "";
    shodan_block = ""

    if routable_ips:
        print(f"   [🔗] Enriching {len(routable_ips)} routable IP(s) concurrently via VT + Shodan MCPs...")
        target_ips = list(routable_ips)[:5]

        # Dispatch tasks concurrently
        vt_tasks = [enrich_ip_via_vt(ip) for ip in target_ips]
        shodan_tasks = [enrich_ip_via_shodan(ip) for ip in target_ips]

        vt_results = await asyncio.gather(*vt_tasks)
        shodan_results = await asyncio.gather(*shodan_tasks)

        vt_block = "\n".join(vt_results)
        shodan_block = "\n".join(shodan_results)
        print(f"   [✓] Dual IP enrichment complete.")
    elif candidate_ips:
        demo_ip = "45.33.32.156"
        print(f"   [🔗] No routable IPs. Demo-enriching {demo_ip} concurrently via VT + Shodan...")
        vt_res, shodan_res = await asyncio.gather(enrich_ip_via_vt(demo_ip), enrich_ip_via_shodan(demo_ip))
        vt_block = f"\n{vt_res}\n"
        shodan_block = f"\n{shodan_res}\n"
        print(f"   [✓] Demo enrichment complete.")
    else:
        print("   [ℹ] No source IPs in alerts. Skipping VT + Shodan.")

    # ── PHASE 2.5: Exploit intel (CONCURRENT) ────────────────────
    service_sigs = extract_service_signatures(mcp_logs)
    exploit_db_block = "";
    vulners_block = ""

    if service_sigs:
        print(f"   [🔗] Detected {len(service_sigs)} service signature(s): {service_sigs}")
        print(f"   [🔗] Querying Exploit Intel MCP concurrently...")
        target_sigs = service_sigs[:3]

        edb_tasks = [enrich_service_via_exploitdb(sig) for sig in target_sigs]
        vulners_tasks = [enrich_service_via_vulners(sig) for sig in target_sigs]

        edb_results = await asyncio.gather(*edb_tasks)
        vulners_results = await asyncio.gather(*vulners_tasks)

        for sig, edb_res, vulners_res in zip(target_sigs, edb_results, vulners_results):
            exploit_db_block += f"\n=== {sig} ===\n{edb_res}\n"
            vulners_block += f"\n=== {sig} ===\n{vulners_res}\n"

        print(f"   [✓] Exploit intel complete.")
    else:
        demo_sig = "ProFTPD 1.3.5"
        print(f"   [🔗] No service signatures. Demo-enriching '{demo_sig}'...")
        edb_res, vulners_res = await asyncio.gather(enrich_service_via_exploitdb(demo_sig),
                                                    enrich_service_via_vulners(demo_sig))
        exploit_db_block = f"\n{edb_res}\n"
        vulners_block = f"\n{vulners_res}\n"
        print(f"   [✓] Demo exploit intel complete.")

    # ── PHASE 2.75: Nuclei live vulnerability scan ───────────────
    nuclei_block = ""
    # Route nuclei to the right target based on which agent generated the alerts
    if "llmgoat" in mcp_logs.lower():
        nuclei_target = NUCLEI_GENAI_TARGET
        print(f"   [🔬] LLMGoat alerts detected. Running Nuclei scan on {nuclei_target}...")
    elif has_web_signals(mcp_logs) or pcap_present:
        nuclei_target = NUCLEI_INFRA_TARGET
        print(f"   [🔬] Web service detected. Running Nuclei scan on {nuclei_target}...")
    else:
        nuclei_target = NUCLEI_INFRA_TARGET
        print(f"   [🔬] Demo scan on {nuclei_target}...")

    nuclei_block = await scan_via_nuclei(nuclei_target)
    print(f"   [✓] Nuclei scan complete ({len(nuclei_block)} chars).")

    # ── PHASE 3: Context decision ────────────────────────────────
    infra_signals = any(k in mcp_logs.lower() for k in [
        "proftpd", "sshd", "samba", "smb", "ftp", "port scan",
        "syslog", "pam", "sudo", "invalid_login", "connection_attempt",
        "recon", "nmap", "metasploit"
    ])
    genai_signals = any(k in mcp_logs.lower() for k in [
        "llmgoat", "prompt injection", "llm", "genai", "a01", "a02",
        "a07", "system prompt", "jailbreak", "challenge"
    ])
    # GenAI takes precedence — if LLMGoat alerts are present, use ATLAS context

    is_infra_attack = (pcap_present or infra_signals) and not genai_signals

    if is_infra_attack:
        print("   [✅] Context locked: INFRASTRUCTURE attack detected.")
        posture_query = "What is the network infrastructure posture and server configuration?"
        framework_query = "What are the OSSTMM and OWASP methodologies for Port Scanning, SMB, and FTP vulnerabilities?"
    else:
        print("   [✅] Context locked: GENAI attack detected.")
        posture_query = "What is the current AI API system posture and recent GenAI security alerts?"
        framework_query = "What are the MITRE ATLAS LLM vulnerabilities and remediation rules?"

    # ── PHASE 4: RAG queries ─────────────────────────────────────
    print("   [🔍] Agent Tool Call: query_database('client_intel')")
    client_intel = query_database("client_intel", posture_query)
    print("   [🔍] Agent Tool Call: query_database('global_frameworks')")
    global_rules = query_database("global_frameworks", framework_query)

    # ── PHASE 5: Build telemetry block ───────────────────────────
    telemetry_data = ""

    if is_infra_attack and pcap_present:
        print("   [🔍] PCAP detected. Engaging Threat Hunter module...")
        json_file = hunt_anomalies("siege_exhaust.pcap")
        if json_file and os.path.exists(json_file):
            with open(json_file, "r") as f:
                telemetry_data += "[NETWORK PCAP ANOMALIES]\n" + f.read() + "\n\n"

    if mcp_logs:
        telemetry_data += "[WAZUH SIEM TELEMETRY (via MCP)]\n" + mcp_logs + "\n\n"
    if vt_block:
        telemetry_data += "[VIRUSTOTAL IP REPUTATION (via MCP)]\n" + vt_block + "\n\n"
    if shodan_block:
        telemetry_data += "[SHODAN HOST EXPOSURE (via MCP)]\n" + shodan_block + "\n\n"
    if exploit_db_block:
        telemetry_data += "[EXPLOIT-DB LOCAL LOOKUP (via MCP)]\n" + exploit_db_block + "\n\n"
    if vulners_block:
        telemetry_data += "[VULNERS AGGREGATED CVE INTEL (via MCP)]\n" + vulners_block + "\n\n"
    if nuclei_block:
        telemetry_data += "[NUCLEI LIVE VULNERABILITY SCAN (via MCP)]\n" + nuclei_block + "\n\n"

    if not telemetry_data:
        telemetry_data = "No telemetry exhaust found in the environment."

        # ── PHASE 6: Enforcement rules ───────────────────────────────
        if is_infra_attack:
            enforcement_rule = (
                "CRITICAL DIRECTIVE: You are analyzing infrastructure security telemetry. "
                "You MUST NOT mention GenAI, prompt injection, LLMs, or web APIs. "
                "Focus EXCLUSIVELY on network ports, services, authentication events, "
                "and host-based alerts proven in the LIVE ATTACK LOGS. "
                "OMNI-SOURCE SYNTHESIS MANDATE: You are provided with a dynamic matrix of intelligence "
                "(Wazuh, PCAP, VirusTotal, Shodan, Exploit-DB, Vulners, Nuclei). "
                "Treat all available sources as equally critical pieces of the puzzle. Analyze them in "
                "intelligent ratios based purely on what data is actively present in the payload. "
                "Do not view any source in isolation. You MUST dynamically cross-reference the available data: "
                "1. Correlate packet-level network anomalies (PCAP) with host-level execution and alerts (Wazuh). "
                "2. Correlate the local attacker IPs (Wazuh/PCAP) with their global threat profiles (VT/Shodan). "
                "3. Correlate the specific targeted services (Nuclei/Wazuh) with known weaponized vulnerabilities (Exploit-DB/Vulners). "
                "If any specific source is absent from the logs below, dynamically adapt your analysis to rely "
                "on the remaining telemetry without mentioning the missing data. Cite specific packet counts, "
                "alert levels, IP reputations, and CVEs to justify your final remediation strategy."
            )
        else:
            enforcement_rule = (
                "CRITICAL DIRECTIVE: You are analyzing GenAI / LLM application security telemetry. "
                "The target is LLMGoat — an intentionally vulnerable LLM application exposing OWASP "
                "Top 10 for LLM vulnerabilities on port 5000. "
                "Focus EXCLUSIVELY on: prompt injection patterns, system prompt leakage attempts, "
                "sensitive data extraction, jailbreak techniques, and LLM API abuse. "
                "You MUST NOT mention traditional network exploits, iptables, FTP, SSH, or SMB. "
                "If VirusTotal or Shodan data is provided, use it to profile the attacker. "
                "If Nuclei data is provided, cite specific LLM-related findings. "
                "Your remediation MUST include: input validation on LLM API endpoints, "
                "system prompt hardening, rate limiting on /api/ routes, and output sanitization."
            )
    else:
        enforcement_rule = (
            "CRITICAL DIRECTIVE: You are analyzing GenAI / LLM application security telemetry. "
            "The target is LLMGoat — an intentionally vulnerable LLM application exposing OWASP "
            "Top 10 for LLM vulnerabilities on port 5000. "
            "Focus EXCLUSIVELY on: prompt injection patterns, system prompt leakage attempts, "
            "sensitive data extraction, jailbreak techniques, and LLM API abuse. "
            "You MUST NOT mention traditional network exploits, iptables, FTP, SSH, or SMB. "
            "If VirusTotal or Shodan data is provided, use it to profile the attacker. "
            "If Nuclei data is provided, cite specific LLM-related findings. "
            "Your remediation MUST include: input validation on LLM API endpoints, "
            "system prompt hardening, rate limiting on /api/ routes, and output sanitization."
        )

    system_prompt = f"""You are the VigilOps Autonomous Security Auditor.
Analyze the Client Intel, Global Frameworks, and LIVE ATTACK LOGS to produce a final risk assessment.

{enforcement_rule}

[DATABASE A: CLIENT INTEL]
{client_intel}

[DATABASE B: GLOBAL FRAMEWORKS (Threat Intel)]
{global_rules}

[LIVE ATTACK LOGS (Penta-Brain MCP Intelligence)]
{telemetry_data}

Instructions:
1. Identify specific attacks in the LIVE ATTACK LOGS.
2. Cross-reference with Global Frameworks.
3. Cite EDB-IDs, CVEs, Nuclei template IDs, VT verdicts, and Shodan exposure data explicitly.
4. Output a structured SECURITY AUDIT REPORT with version-specific, actionable mitigation steps.
Concise, professional, no filler words.
"""

    payload = {"model": LLM_MODEL, "prompt": system_prompt, "stream": False}

    print(f"   [⏳] Waiting for {LLM_MODEL} to generate the Master Audit...\n")
    try:
        response = requests.post(OLLAMA_URL, json=payload)
        if response.status_code != 200:
            print(f"[!] OLLAMA ERROR: {response.text}")
            return

        response_data = response.json()
        raw_text = response_data.get("response", "")
        final_report = raw_text

        print("==================================================")
        print("🛡️ VIGILOPS MASTER SECURITY AUDIT 🛡️")
        print("==================================================")

        if "<think>" in raw_text:
            parts = raw_text.split("</think>")
            if len(parts) > 1:
                think_process = parts[0].replace("<think>", "").strip()
                final_report = parts[1].strip()
                print("\n[AGENT INTERNAL REASONING]")
                print(think_process[:300] + "...\n")
                print("[FINAL REPORT]")
                print(final_report)
            else:
                print(raw_text)
        else:
            print(raw_text)

        print("\n==================================================")
        print("🛠️ VIGILOPS EXECUTION ENGINE 🛠️")
        print("==================================================")
        codex_engineer.generate_patch(final_report)

    except requests.exceptions.ConnectionError:
        print("[!] ERROR: Cannot connect to Ollama.")


# ==============================================================
#  ENTRY POINT
# ==============================================================

if __name__ == "__main__":
    # Fire the fully concurrent asynchronous pipeline
    asyncio.run(run_agentic_audit())