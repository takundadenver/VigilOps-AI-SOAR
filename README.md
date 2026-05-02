# VigilOps 2.0: Autonomous Purple Team & AI SOAR 🛡️
*Built for the OpenAI x Handshake Codex Creator Challenge & MLSecOps Research*

VigilOps is a next-generation, closed-loop Security Orchestration, Automation, and Response (SOAR) platform designed specifically to defend Generative AI Applications against novel threats like Prompt Injections, Jailbreaks, and Data Poisoning. 

It pioneers a **3-Pillar MLSecOps Architecture**:
1. **Automated GRC Auditing:** Real-time mapping of AI telemetry to the NIST AI RMF.
2. **AI-on-AI Offensive Teaming:** Automated adversarial network simulation.
3. **AI-Specific SOAR:** Autonomous, context-aware remediation scripting.

## 🧠 The Architecture (The Infinity Loop)

* **The Attacker (Clawbot):** A Python script simulating a Cloud VPS firing continuous MITRE ATLAS AI attacks at an exposed Flask honeypot.
* **The Detector (Wazuh Framework):** Monitors volatile server logs and alerts the SOAR pipeline in real-time.
* **The Memory (ChromaDB / RAG):** Using `nomic-embed-text`, VigilOps queries corporate Standard Operating Procedures (SOPs) offline to ensure remediation adheres to specific network topologies.
* **The Brain (DeepSeek 14B):** A locally-hosted LLM analyzes the payload, maps it to the OWASP Top 10 for LLMs, and prescribes a custom remediation strategy inside a strict execution sandbox.
* **The Engineer (OpenAI API / Codex):** VigilOps parses the Analyst's recommendation and passes it securely to OpenAI. OpenAI dynamically generates a fully functional Python firewall-patching script on the fly.
* **Execution:** After Human-In-The-Loop (HITL) approval, the OpenAI-generated script is executed to block the attacker instantly.

## 🛠️ Built With
* **OpenAI API** (Dynamic remediation code generation)
* **Python** (Flask, Requests, Subprocess workflows)
* **ChromaDB** (Retrieval-Augmented Generation)
* **Ollama** (Local DeepSeek-R1 for privacy-first, air-gapped threat analysis)

## 🚀 How to Run
1. Run `python vulnerable_app.py` to start the honeypot.
2. Run `python rag_builder.py` to ingest the company SOPs into ChromaDB.
3. Add your OpenAI API Key to `codex_engineer.py` as an environment variable.
4. Run `python main.py` to start the SOAR Warden.
5. Run `python clawbot_attacker.py` to launch the attack and watch the pipeline automatically secure the network!

---
*Copyright (c) 2026 Denver Zimunya. All Rights Reserved. This repository contains a sanitized proof-of-concept for the VigilOps architecture. Core analytical logic, vector databases, and enterprise configurations remain proprietary and localized.*
