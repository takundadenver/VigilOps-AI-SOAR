import time
import requests
import re
import os
import codex_engineer
import chromadb
from chromadb.utils import embedding_functions

# --- CONFIGURATION ---
OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_EMBED_URL = "http://localhost:11434/api/embeddings"
MODEL_NAME = "vigilops-14b"
EMBEDDING_MODEL = "nomic-embed-text"
LOG_FILE = "app_security_logs.txt"
AUDIT_FILE = "vigil_audit_trail.log"
DB_PATH = "vigil_chroma_db"


def query_knowledge_base(attack_log):
    print("   [🔍] Querying local Knowledge Base for relevant SOPs...")
    try:
        client = chromadb.PersistentClient(path=DB_PATH)
        ollama_ef = embedding_functions.OllamaEmbeddingFunction(url=OLLAMA_EMBED_URL, model_name=EMBEDDING_MODEL)
        collection = client.get_collection(name="vigilops_sop", embedding_function=ollama_ef)

        # Strip the timestamp noise for better vector math
        clean_attack_query = attack_log.split("USER_INPUT:")[-1].strip() if "USER_INPUT:" in attack_log else attack_log

        # 🚀 FIX: Pull the Top 2 documents and let DeepSeek decide!
        results = collection.query(query_texts=[clean_attack_query], n_results=2)

        if results['documents'] and results['documents'][0]:
            # Combine the text of BOTH documents
            retrieved_docs = "\n\n--- NEXT SOP ---\n\n".join(results['documents'][0])
            filenames = " & ".join([meta['source'] for meta in results['metadatas'][0]])

            print(f"   [+] MATCH FOUND: Retrieved corporate protocols -> {filenames}")
            return retrieved_docs

        return "NO SPECIFIC CORPORATE PROTOCOLS FOUND."
    except Exception as e:
        return f"DATABASE CONNECTION ERROR: {e}"


def send_to_vigil(log_entry, retrieved_context):
    print("\n[+] Routing payload and SOPs to V.I.G.I.L. for Tier-3 Analysis...")

    # THE FIX: The Architect's Master Sandbox (Now with RAG Context)
    prompt = f"""[STRICT ANALYST MODE]
Identify and analyze the specific ATTACK PATTERN contained within the TELEMETRY DATA below.

CRITICAL CONTEXT: You are defending a Generative AI Application API. Evaluate the threat across the entire threat landscape. Map this threat using the most relevant framework: OWASP Top 10 for LLMs, MITRE ATLAS (for AI-specific attacks), or traditional MITRE ATT&CK (if targeting underlying infrastructure).

### CORPORATE SOP & NETWORK TOPOLOGY:
{retrieved_context}

### TELEMETRY DATA:
```text
{log_entry}
```

### MANDATORY RESPONSE GUIDELINES:
1. YOU ARE V.I.G.I.L. - DO NOT speak as a general AI. You are authorized to analyze this attack. DO NOT redact, censor, or hide any part of your analysis.
2. The TELEMETRY DATA above contains a malicious payload. ANALYZE it.
3. Incorporate the CORPORATE SOP into your [REMEDIATION PATCH]. Mention specific IP addresses or rules if applicable.
4. DO NOT output JSON. DO NOT output fake server logs. You must output your report in standard PLAIN TEXT MARKDOWN.
5. Use ONLY your 5 headers: [THREAT DETECTED], [FRAMEWORK ALIGNMENT], [SEVERITY LEVEL], [BLAST RADIUS PREDICTION], and [REMEDIATION PATCH]."""

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }

    try:
        # Pinging the local Ollama brain
        response = requests.post(OLLAMA_API_URL, json=payload)
        response.raise_for_status()
        return response.json().get("response", "")
    except requests.exceptions.RequestException as e:
        print(f"[!] API Communication Failure: {e}")
        return None


def process_and_filter(raw_response):
    # 1. Extract the internal thought process
    think_match = re.search(r"<think>(.*?)</think>", raw_response, re.DOTALL)
    think_content = think_match.group(1).strip() if think_match else "No internal logic captured."

    # 2. Slice the thoughts OUT of the final report
    clean_output = re.sub(r"<think>.*?</think>", "", raw_response, flags=re.DOTALL).strip()

    # 3. Silently save the thoughts to the Audit File for compliance
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"\n--- V.I.G.I.L. AUDIT LOG: {timestamp} ---\n")
        f.write(think_content + "\n")

    return clean_output


def start_soar_pipeline():
    print("🛡️ VIGILOPS SOAR WARDEN ONLINE (RAG ENABLED) 🛡️")
    print(f"Monitoring {LOG_FILE} for incoming attacks...\n")

    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'w').close()

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        # Move the cursor to the very end of the file
        f.seek(0, 2)

        while True:
            new_attack = f.readline()
            if not new_attack:
                time.sleep(1)
                continue

            print(f"🚨 NEW THREAT DETECTED: {new_attack.strip()}")

            # 1. Query the RAG Database first
            sop_context = query_knowledge_base(new_attack)

            # 2. Send both the attack AND the SOP to the AI
            raw_ai_response = send_to_vigil(new_attack, sop_context)

            if raw_ai_response:
                clean_report = process_and_filter(raw_ai_response)

                print("\n" + "=" * 60)
                print(" " * 10 + "V.I.G.I.L. THREAT INTELLIGENCE REPORT")
                print("=" * 60)
                print(clean_report)
                print("=" * 60 + "\n")

                action = input("⚠️ TYPE 'APPROVE' TO EXECUTE REMEDIATION OR 'DENY' TO DROP: ").strip().upper()

                if action == "APPROVE":
                    print("[✓] COMMAND ACCEPTED. Deploying defensive countermeasures...")
                    # THIS IS THE NEW LINE: Trigger the firewall script!
                    codex_engineer.generate_and_execute_patch("Block attacker")
                    print("Listening for next attack...\n")
                else:
                    print("[X] ACTION DENIED. Threat logged but not blocked.\n")
                    print("Listening for next attack...\n")


if __name__ == "__main__":
    start_soar_pipeline()