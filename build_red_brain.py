import os
import chromadb


def build_offensive_database():
    print("\n==================================================")
    print("🧠 VIGILOPS: BUILDING DUAL-SEGMENT RAG BRAIN 🧠")
    print("==================================================")

    db_path = "./red_brain_db"
    chroma_client = chromadb.PersistentClient(path=db_path)

    # Define our two intelligence scopes
    scopes = {
        "infra": "./offensive_playbooks/infra",
        "genai": "./offensive_playbooks/genai"
    }

    for scope_name, folder_path in scopes.items():
        collection_name = f"playbooks_{scope_name}"

        # Reset the collection
        try:
            chroma_client.delete_collection(name=collection_name)
        except Exception:
            pass

        collection = chroma_client.create_collection(name=collection_name)

        if not os.path.exists(folder_path):
            os.makedirs(folder_path)  # Create it if it doesn't exist
            print(f"[-] Directory {folder_path} was missing. Created it.")
            continue

        doc_id = 0
        print(f"[*] Scanning {folder_path} for {scope_name.upper()} tradecraft...")

        for filename in os.listdir(folder_path):
            if filename.endswith(".txt") or filename.endswith(".md"):
                filepath = os.path.join(folder_path, filename)
                with open(filepath, 'r', encoding='utf-8') as file:
                    content = file.read()

                    chunks = content.split('\n\n')
                    for chunk in chunks:
                        if chunk.strip():
                            collection.add(
                                documents=[chunk.strip()],
                                metadatas=[{"source": filename}],
                                ids=[f"{scope_name}_doc_{doc_id}"]
                            )
                            doc_id += 1
                print(f"   [+] Ingested: {filename}")

        print(f"[✓] {scope_name.upper()} Brain compiled with {doc_id} tactical vectors.\n")


if __name__ == "__main__":
    build_offensive_database()