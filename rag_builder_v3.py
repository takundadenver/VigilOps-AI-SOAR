import chromadb
from chromadb.utils import embedding_functions
import os

# ---------------------------------------------------------
# VIGILOPS V3: DUAL-SEGMENTED RAG BUILDER
# Purpose: Ingests data into two separate vector databases
# to prevent context-bleeding between Client logs and Global rules.
# ---------------------------------------------------------

# Configuration
DB_PATH = "vigil_chroma_db_v3"  # New folder so we don't break V2
OLLAMA_EMBED_URL = "http://localhost:11434/api/embeddings"
EMBEDDING_MODEL = "nomic-embed-text"

# Setup ChromaDB Client
client = chromadb.PersistentClient(path=DB_PATH)
ollama_ef = embedding_functions.OllamaEmbeddingFunction(
    url=OLLAMA_EMBED_URL,
    model_name=EMBEDDING_MODEL
)


def create_dummy_global_framework():
    """Generates a dummy global framework file for testing."""
    os.makedirs("global_frameworks", exist_ok=True)
    framework_path = "global_frameworks/OWASP_Top_10_LLM.txt"
    if not os.path.exists(framework_path):
        with open(framework_path, "w") as f:
            f.write("""[GLOBAL FRAMEWORK: OWASP Top 10 for LLMs]
LLM01: Prompt Injection - Attackers manipulate LLM inputs to bypass filters.
Remediation: Sanitize inputs, enforce strict system prompts, and use WAF rate-limiting.

LLM06: Sensitive Information Disclosure - LLMs inadvertently reveal PII or proprietary data.
Remediation: Implement strict data masking and monitor DB access logs via SIEM.""")
        print("[*] Created dummy OWASP Global Framework for testing.")


def build_client_intel_db():
    """Ingests the Recon Agent's output into Collection A."""
    print("\n[+] Building Database A: Client Intel...")
    collection_a = client.get_or_create_collection(
        name="client_intel",
        embedding_function=ollama_ef
    )

    intel_file = "unified_client_intel.txt"
    if os.path.exists(intel_file):
        with open(intel_file, "r", encoding="utf-8") as f:
            content = f.read()
            # In a production app, we would 'chunk' this text.
            # For now, we ingest the whole report as one document.
            collection_a.upsert(
                documents=[content],
                metadatas=[{"source": "recon_agent_v3", "type": "live_telemetry"}],
                ids=["client_intel_latest"]
            )
        print("   [✓] Client Intel ingested successfully!")
    else:
        print("   [!] ERROR: unified_client_intel.txt not found. Run recon_agent.py first.")


def build_global_frameworks_db():
    """Ingests OWASP, NIST, and Threat Intel into Collection B using Strict Chunking."""
    print("\n[+] Building Database B: Global Frameworks...")
    collection_b = client.get_or_create_collection(
        name="global_frameworks",
        embedding_function=ollama_ef
    )

    framework_dir = "global_frameworks"
    docs = []
    metas = []
    doc_ids = []

    if os.path.exists(framework_dir):
        for filename in os.listdir(framework_dir):
            if filename.endswith(".txt"):
                with open(os.path.join(framework_dir, filename), "r", encoding="utf-8") as f:
                    content = f.read()

                    # 👇 THE BULLETPROOF FIX: Strict 1500-character limits 👇
                    import textwrap
                    chunks = textwrap.wrap(content, width=1500, break_long_words=False, replace_whitespace=False)

                    for i, chunk in enumerate(chunks):
                        if chunk.strip():
                            docs.append(chunk.strip())
                            metas.append({"source": filename, "type": "global_compliance"})
                            doc_ids.append(f"{filename}_chunk_{i}")

        if docs:
            collection_b.upsert(
                documents=docs,
                metadatas=metas,
                ids=doc_ids
            )
            print(f"   [✓] Global Frameworks ingested successfully! ({len(docs)} strict chunks created)")
        else:
            print("   [!] No valid text found in global_frameworks folder.")
    else:
        print("   [!] ERROR: global_frameworks folder not found.")


if __name__ == "__main__":
    print("🛡️ VIGILOPS V3: INITIALIZING DUAL-BRAIN DATABASE")
    print("--------------------------------------------------")
    create_dummy_global_framework()
    build_client_intel_db()
    build_global_frameworks_db()
    print("--------------------------------------------------")
    print("[✓] Dual-Segmented RAG Database Ready for Orchestrator Queries.")