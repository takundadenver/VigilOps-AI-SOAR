VigilOps V3: Unified AI-SPM & Autonomous Red Team Platform 🛡️
An Agentic AI Security Posture Management (AI-SPM), Incident Response, and GRC Architecture

VigilOps is a next-generation, closed-loop Security Orchestration, Automation, and Response (SOAR) platform designed specifically to secure Generative AI infrastructure. It moves beyond traditional signature-based detection by bridging host systems architecture, live global threat intelligence, and Agentic Machine Learning into one cohesive, autonomous platform.

🏗️ The "Tri-Brain" Architecture
VigilOps executes an autonomous "Infinity Loop" across three core operational pillars:

Pillar 1: AI GRC & Posture Management (The Shield)
Data Diode (Threat Intel Scraper): A lightweight utility that actively scrapes live, real-world CVEs and threat alerts from CISA and Hacker News to arm the defense AI with zero-day knowledge.

Forward-Deployed Recon: A local Python agent (agent_recon.py) deployed on the target host to map system posture, open network ports, and aggregate live system telemetry.

Dual-Segmented RAG Database: The system sanitizes and pipes this live telemetry into a client_intel collection in ChromaDB, completely isolated from a secondary global_frameworks collection (NIST AI RMF, OWASP Top 10 for LLMs, MITRE ATLAS, and live CISA alerts).

Pillar 2: Autonomous Red Teaming (The Sword)
The Target Honeypot: A vulnerable local Flask API endpoint mimicking an enterprise AI chatbot, designed to absorb attacks and generate live telemetry.

Adversarial Engine (HoneyBadger 3.0): Replacing traditional static scripts, HoneyBadger is a relentless, cloud-powered offensive agent. It utilizes an "Engagement Scope" to dynamically invent novel MITRE ATLAS payloads (Prompt Injections, Jailbreaks) or traditional infrastructure attacks (SQLi, Directory Fuzzing) and actively slams them into the target.

Telemetry Exhaust (PCAP & Logs): The moment an attack initiates, the platform automatically triggers background packet captures (tshark) locked to specific network adapters. The honeypot simultaneously catches the exact payloads, creating a dual-layered forensic crime scene (app_security_logs.txt and siege_exhaust.pcap).

Pillar 3: AI-Specific SOAR (The Executioner)
Multi-Agent Orchestration: The AI-SOAR pipeline operates using a "Brain and Hands" multi-tier routing architecture. A high-speed, low-cost model (gpt-4o-mini) acts as a Tier 1 SOC Analyst to filter massive log files, isolating malicious payloads. The payload is then escalated to the "Brain" (DeepSeek-V3.2/R1), acting as a Tier 3 Responder, to perform deep chain-of-thought forensics and map the breach to MITRE ATT&CK.

Automated Remediation (Codex): The resulting Master Security Audit is securely passed to an external execution engine. The engine dynamically translates the audit into a flawless Python infrastructure-as-code (IaC) patching script (generated_firewall_patch.py), targeting tools like AWS WAF and Palo Alto rate-limiting.

🛠️ Built With
Python 3.13 (psutil OS scraping, Subprocess workflows, Multi-Agent routing)

ChromaDB (Dual-Segmented Retrieval-Augmented Generation)

DeepSeek-R1 / V3.2 (High-fidelity, chain-of-thought forensic reasoning and orchestration)

OpenAI gpt-4o-mini / Codex (High-speed task execution, loop management, and IaC generation)

Wireshark / TShark (Automated network telemetry exhaust)

Boto3 & Requests (Enterprise infrastructure API integrations)

🚀 How to Run (The Command Center)
The entire suite is seamlessly controlled via a centralized CLI dashboard.

Run python main.py to launch the VIGILOPS_CMD Master Interface.

Execute [1] to pull live internet threat intel via the Data Diode.

Execute [2] to run local system reconnaissance.

Execute [3] to compile the Dual-Segmented vector databases.

Execute [4] to detach and spin up the Flask honeypot.

Execute [5] to unleash the HoneyBadger siege (Features an Engagement Scope toggle for GenAI vs Infra targets).

Execute [6] to wake up the Orchestrator, analyze the damage, and generate your firewall patch!

🔬 Technical Innovations & Deep Dive
To make VigilOps function autonomously without overwhelming local hardware or API limits, several advanced DevSecOps engineering techniques were implemented under the hood:

The "Brain vs. Hands" Multi-Tier LLM Architecture: To maximize intelligence while minimizing API runaway costs, workloads are routed based on cognitive requirements. High-speed, repetitive tasks (executing terminal loops, parsing massive HTML/HTTP logs) are handled by efficient models ("The Hands"). Complex, strategic tasks (generating multi-step attack strategies, forensic incident response) are escalated to heavy-reasoning models like DeepSeek ("The Brain").

RAG Engagement Scoping: To prevent "Vector Dilution" (where the AI hallucinates SQL injections during an LLM Prompt Injection test), the ChromaDB architecture is physically segregated. Operators select Rules of Engagement (RoE) prior to the siege, forcing the AI to query isolated intelligence collections.

Cognitive Escalation Playbooks: The RAG ingestion engine utilizes specialized chunking rules to ingest entire MITRE ATT&CK kill-chains as cohesive thoughts. This grants HoneyBadger true agentic pivoting capabilities—if a payload results in a 404 Not Found, the agent reads the terminal output, consults the escalation path, and dynamically pivots to directory fuzzing without human intervention.

Context Splicing & Token Safety: To prevent the context window from degrading during autonomous loops, the platform enforces hard token limits and memory wipes. Massive Intel payloads and Nmap scans are dynamically spliced before hitting the LLM to prevent hallucination and API death loops.

Copyright (c) 2026 Denver Zimunya. All Rights Reserved. This repository contains a sanitized proof-of-concept for the VigilOps architecture. Core analytical logic, proprietary vector databases, and enterprise execution configurations remain strictly localized.
