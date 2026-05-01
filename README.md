VigilOps: Autonomous Purple Team & AI SOAR 🛡️

Built for the OpenAI x Handshake Codex Creator Challenge

VigilOps is a next-generation, closed-loop Security Orchestration, Automation, and Response (SOAR) platform designed specifically to defend Generative AI Applications against novel threats like Prompt Injections, Jailbreaks, and Data Poisoning.

🧠 The Architecture (The Infinity Loop)

The Attacker (Clawbot): A Python script simulating a Cloud VPS firing continuous MITRE ATLAS AI attacks at an exposed Flask honeypot.

The Detector (Wazuh Framework): Monitors volatile server logs and alerts the SOAR pipeline in real-time.

The Memory (ChromaDB / RAG): Using nomic-embed-text, VigilOps queries corporate Standard Operating Procedures (SOPs) offline to ensure remediation adheres to specific network topologies.

The Brain (DeepSeek 14B): A locally-hosted LLM analyzes the payload, maps it to the OWASP Top 10 for LLMs, and prescribes a custom remediation strategy.

The Engineer (OpenAI API / Codex): VigilOps parses the Analyst's recommendation and passes it securely to OpenAI. OpenAI dynamically generates a fully functional Python firewall-patching script on the fly.

Execution: After Human-In-The-Loop (HITL) approval, the OpenAI-generated script is executed to block the attacker instantly.

🛠️ Built With

OpenAI API (Codex replacement for code generation)

Python (Flask, Requests)

ChromaDB (Retrieval-Augmented Generation)

Ollama (Local DeepSeek-R1 for privacy-first analysis)

🚀 How to Run

Run python vulnerable_app.py to start the honeypot.

Run python rag_builder.py to ingest the company SOPs into ChromaDB.

Add your OpenAI API Key to codex_engineer.py.

Run python main.py to start the Warden.

Run python clawbot_attacker.py to launch the attack and watch the pipeline automatically secure the network!