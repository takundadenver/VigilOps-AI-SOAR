import chromadb
from chromadb.utils import embedding_functions
import requests
import json
import os
import codex_engineer  # <--- IMPORTING THE EXECUTION ENGINE

# ---------------------------------------------------------
# VIGILOPS V3: AGENTIC ORCHESTRATOR
# Purpose: Queries the Dual-Brain RAG, reads live attack logs,
# and uses DeepSeek to generate a master security audit.
# ---------------------------------------------------------

DB_PATH = "vigil_chroma_db_v3"
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_EMBED_URL = "http://localhost:11434/api/embeddings"
EMBEDDING_MODEL = "nomic-embed-text"
LLM_MODEL = "vigilops-14b" # Your local DeepSeek model


def query_database(collection_name, query_text):
    try:
        client = chromadb.PersistentClient(path=DB_PATH)
        ollama_ef = embedding_functions.OllamaEmbeddingFunction(url=OLLAMA_EMBED_URL, model_name=EMBEDDING_MODEL)
        collection = client.get_collection(name=collection_name, embedding_function=ollama_ef)

        results = collection.query(query_texts=[query_text], n_results=1)
        if results['documents'] and results['documents'][0]:
            return results['documents'][0][0]
        return "No data found."
    except Exception as e:
        return f"Database Error: {e}"


def run_agentic_audit():
    print("🧠 VIGILOPS ORCHESTRATOR: Waking up...")

    print("   [🔍] Agent Tool Call: query_database('client_intel')")
    client_intel = query_database("client_intel", "What is the current system posture, open ports, and recent security alerts?")

    print("   [🔍] Agent Tool Call: query_database('global_frameworks')")
    global_rules = query_database("global_frameworks", "What are the MITRE ATLAS LLM vulnerabilities and remediation rules?")

    # 👇 THE NEW ADDITION: Reading the HoneyBadger Crime Scene 👇
    print("   [📥] Fetching Live SIEM Telemetry (app_security_logs.txt)...")
    live_logs = "No active attacks detected."
    if os.path.exists("app_security_logs.txt"):
        with open("app_security_logs.txt", "r", encoding="utf-8") as f:
            # Grab the last 15 lines of the log file so we only see the most recent attacks
            lines = f.readlines()
            live_logs = "".join(lines[-15:])

    print("   [⚙️] Agent Reasoning: Passing context to DeepSeek for analysis...")

    system_prompt = f"""You are the VigilOps Autonomous Security Auditor.
Your job is to analyze the Client Intel, Global Frameworks, and the LIVE ATTACK LOGS to provide a final risk assessment and remediation plan.

[DATABASE A: CLIENT INTEL]
{client_intel}

[DATABASE B: GLOBAL FRAMEWORKS (Threat Intel)]
{global_rules}

[LIVE ATTACK LOGS (HoneyBadger Telemetry)]
{live_logs}

Instructions:
1. Identify the specific attacks happening in the LIVE ATTACK LOGS.
2. Cross-reference them with the Global Frameworks.
3. Output a structured SECURITY AUDIT REPORT with a specific mitigation strategy to block these attacks.
Keep it concise, professional, and actionable. Do not use filler words.
"""

    payload = {
        "model": LLM_MODEL,
        "prompt": system_prompt,
        "stream": False
    }

    print(f"   [⏳] Waiting for {LLM_MODEL} to generate the Master Audit...\n")
    try:
        response = requests.post(OLLAMA_URL, json=payload)

        if response.status_code != 200:
            print(f"[!] OLLAMA API ERROR: {response.text}")
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

        # -----------------------------------------------------
        # THE HANDOFF: PASSING THE AUDIT TO OPENAI FOR PATCHING
        # -----------------------------------------------------
        print("\n==================================================")
        print("🛠️ VIGILOPS EXECUTION ENGINE 🛠️")
        print("==================================================")
        codex_engineer.generate_patch(final_report)

    except requests.exceptions.ConnectionError:
        print("[!] ERROR: Cannot connect to Ollama. Make sure Ollama is running.")


if __name__ == "__main__":
    run_agentic_audit()