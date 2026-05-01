import os
import chromadb
from chromadb.utils import embedding_functions

# --- CONFIGURATION ---
KNOWLEDGE_BASE_DIR = "vigil_knowledge_base"
DB_PATH = "vigil_chroma_db"
OLLAMA_URL = "http://localhost:11434/api/embeddings"
EMBEDDING_MODEL = "nomic-embed-text"


def build_vector_db():
    print("🧠 Booting up VigilOps RAG Ingestion Engine...")

    # 1. Initialize ChromaDB (Persistent storage saves the vectors to your hard drive)
    client = chromadb.PersistentClient(path=DB_PATH)

    # 2. Configure the local Ollama Embedding Model
    print(f"🔌 Connecting to local embedding model: {EMBEDDING_MODEL}")
    ollama_ef = embedding_functions.OllamaEmbeddingFunction(
        url=OLLAMA_URL,
        model_name=EMBEDDING_MODEL,
    )

    # 3. Create or grab the collection (Think of this like a SQL table for AI)
    collection = client.get_or_create_collection(
        name="vigilops_sop",
        embedding_function=ollama_ef
    )

    # 4. Read files from our Knowledge Base folder
    if not os.path.exists(KNOWLEDGE_BASE_DIR):
        print(f"[!] Directory '{KNOWLEDGE_BASE_DIR}' not found. Please create it.")
        return

    documents = []
    metadatas = []
    ids = []

    print(f"📂 Scanning '{KNOWLEDGE_BASE_DIR}' for company documents...")
    for filename in os.listdir(KNOWLEDGE_BASE_DIR):
        if filename.endswith(".txt"):
            file_path = os.path.join(KNOWLEDGE_BASE_DIR, filename)
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()

                # Prep the data for ChromaDB
                documents.append(content)
                metadatas.append({"source": filename})
                ids.append(filename)  # Use the filename as the unique ID
                print(f"   [+] Loaded: {filename}")

    # 5. Push to Database
    if documents:
        print("⚙️  Vectorizing text and saving to database... (This might take a few seconds)")

        # We use an 'upsert' so if we run this script again later, it updates changed files instead of duplicating
        collection.upsert(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        print("\n✅ RAG Database successfully built and populated!")
        print(f"📊 Total documents in database: {collection.count()}")
    else:
        print("[!] No .txt files found in the knowledge base.")


if __name__ == "__main__":
    build_vector_db()