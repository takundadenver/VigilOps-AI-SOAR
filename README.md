# VigilOps 3.0: Unified MLSecOps & Autonomous Purple Team 🛡️
*An Air-Gapped AI Incident Response and GRC Auditing Architecture*

VigilOps is a next-generation, closed-loop Security Orchestration, Automation, and Response (SOAR) platform designed specifically to secure Generative AI Applications. It moves beyond traditional signature-based detection by bridging systems architecture, network telemetry, and advanced machine learning into one cohesive, localized platform.

## 🏗️ The 3-Pillar Architecture

VigilOps executes an autonomous "Infinity Loop" across three core operational pillars:

### Pillar 1: The GRC Auditor (The Shield)
* **The Infiltration:** A lightweight Python agent (`vigil_agent.py`) is deployed alongside the Wazuh SIEM host. It silently maps system posture, hardware specs, and ingests local network policies and SOPs.
* **Dual-Hemisphere RAG:** The agent sanitizes and pipes this local data into the `Client_Intel` collection in ChromaDB, while keeping compliance frameworks (NIST AI RMF, ISO 42001) in a separate `Governance_Frameworks` collection.
* **Context-Aware Auditing:** A localized DeepSeek-R1 14B model cross-references the environment against the frameworks to automatically generate risk assessments without firing a single payload.

### Pillar 2: Offensive AI Engine (The Sword)
* **Autonomous Red Teaming:** The `clawbot_attacker.py` engine fires continuous, adversarial MITRE ATLAS payloads (Prompt Injections, Jailbreaks, Data Poisoning) at the target LLM/Application.
* **The Telemetry Catch:** During the siege, the Wazuh SIEM and `vigil_agent` capture the exact moment the target LLM hallucinates or leaks data, compiling the volatile logs into a "Crash Report."

### Pillar 3: AI-Specific SOAR (The Brain)
* **Tier-3 Analysis:** DeepSeek ingests the Crash Report, queries the `Client_Intel` database to understand the specific network topology, and determines the exact logic needed to patch the vulnerability.
* **Automated Remediation:** The logic is securely passed to an external API bridge (OpenAI Codex/Claude). The model dynamically generates a flawless Python/Bash firewall or API patching script.
* **Execution:** After Human-In-The-Loop (HITL) approval, the script is executed, neutralizing the zero-day threat in real-time.

## 🛠️ Built With
* **Python** (Flask, Subprocess workflows, Local Agents)
* **ChromaDB** (Dual-Hemisphere Retrieval-Augmented Generation)
* **Ollama / DeepSeek-R1 14B** (Privacy-first, air-gapped threat analysis)
* **OpenAI Codex / Claude API** (Dynamic remediation code generation)
* **Wazuh** (SIEM Telemetry)

## 🚀 How to Run (Sanitized PoC)
1. Run `python rag_builder.py` to initialize the Dual-Hemisphere ChromaDB.
2. Deploy `python vigil_agent.py` to scrape local host telemetry and populate the `Client_Intel` RAG.
3. Run `python vulnerable_app.py` to start the Flask AI honeypot.
4. Run `python main.py` to start the SOAR Warden pipeline.
5. Run `python clawbot_attacker.py` to launch the MITRE ATLAS siege and watch the pipeline autonomously secure the network!

---
*Copyright (c) 2026 Denver Zimunya. All Rights Reserved. This repository contains a sanitized proof-of-concept for the VigilOps architecture. Core analytical logic, proprietary vector databases, and enterprise execution configurations remain strictly localized.*
