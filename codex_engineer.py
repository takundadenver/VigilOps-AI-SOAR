import os
import requests
import json

# ---------------------------------------------------------
# VIGILOPS V3: CODEX ENGINEER (OPENAI) — DOMAIN-AWARE
# Purpose: Receives the Master Audit from the Orchestrator
# and dynamically writes the Python remediation patch that
# matches the attack's actual domain (host / network / web).
# ---------------------------------------------------------

# Securely fetch the API key from the system environment
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")

def generate_patch(master_audit):
    print("\n[🤖] Waking up Codex Engineer (OpenAI)...")
    print("   [⚙️] Translating Master Audit into executable Python code...")

    if not OPENAI_API_KEY:
        print("   [!] ERROR: OPENAI_API_KEY environment variable not found!")
        print("   [!] Please set it in your Windows terminal using:")
        print("   [!] setx OPENAI_API_KEY \"your_actual_api_key_here\"")
        return

    # ── DOMAIN DETECTION ────────────────────────────────────────
    # Inspect the audit text and tag the dominant attack domain.
    audit_lower = master_audit.lower()

    host_signals = [
        "sudo", "pam", "/etc/", "ssh", "auditd", "useradd", "passwd",
        "privilege escalation", "root privilege", "least privilege",
        "sudoers", "rootcheck", "host-based", "/var/log",
        "kernel", "systemd", "selinux", "apparmor", "cron",
        "file permissions", "file integrity", "process injection",
        "memory tampering", "ld_preload"
    ]

    network_signals = [
        "port scan", "nmap", "lateral movement", "firewall",
        "smb", "rdp", "ddos", "syn flood", "ingress", "egress",
        "ftp", "proftpd", "brute-force", "connection attempts",
        "iptables", "fail2ban", "ip block", "reverse shell",
        "auth failure", "invalid_login", "metasploit", "exploit framework",
        "netflow", "packet capture", "pcap", "perimeter",
        "network segmentation", "vlan", "ssh brute"
    ]

    web_signals = [
        # Generic web-app vulns
        "prompt injection", "sqli", "sql injection", "xss", "csrf",
        "ssrf", "rce", "remote code execution", "deserialization",
        "owasp top 10", "owasp a01", "owasp a03", "owasp a07",
        "drupal", "wordpress", "tomcat", "jenkins", "phpmyadmin",
        "web application", "input validation", "session hijacking",
        "directory traversal", "lfi", "rfi", "api key", "jwt",
        # GenAI / LLM-specific
        "genai", "gen ai", "generative ai", "llm", "large language model",
        "model abuse", "jailbreak", "model extraction", "model poisoning",
        "prompt leak", "system prompt leak", "data leakage from llm",
        "hallucination", "ai api", "openai api", "anthropic api",
        "mitre atlas", "atlas framework", "ai supply chain",
        "training data poisoning", "agentic abuse", "tool use abuse",
        "rag poisoning", "vector database poisoning", "embedding attack"
    ]

    host_score = sum(s in audit_lower for s in host_signals)
    net_score  = sum(s in audit_lower for s in network_signals)
    web_score  = sum(s in audit_lower for s in web_signals)

    domain = max(
        [("HOST", host_score), ("NETWORK", net_score), ("WEB", web_score)],
        key=lambda x: x[1]
    )[0]

    print(f"   [🔍] Attack domain detected: {domain}")

    # ── DOMAIN-SPECIFIC INSTRUCTIONS ────────────────────────────
    if domain == "HOST":
        domain_instructions = """
This is a HOST-LEVEL attack (privilege escalation, sudo, PAM, file permissions).
Generate Python code that uses subprocess to apply technical remediation on the Linux host:
- Harden /etc/sudoers via 'visudo -c' validation and adding 'Defaults logfile=/var/log/sudo.log'
- Add auditd rules to /etc/audit/rules.d/sudo.rules for sudo execution logging
- Configure PAM modules in /etc/pam.d/sudo to enforce session limits
- Restart auditd via systemctl
- NEVER call firewall APIs, NEVER use boto3, NEVER call Palo Alto endpoints
"""
    elif domain == "NETWORK":
        domain_instructions = """
This is a NETWORK-LAYER attack (port scanning, lateral movement, network reconnaissance).
Generate Python code that:
- Uses subprocess to apply iptables/ufw rules blocking attacker source IPs
- OR uses 'requests' to call a Palo Alto NGFW REST API for blocking rules
- OR uses 'boto3' for AWS WAF IPSet updates if the audit references cloud infrastructure
- Choose whichever the audit explicitly names. Default to iptables if unclear.
"""
    else:  # WEB
        domain_instructions = """
This is a WEB-APPLICATION attack (SQLi, XSS, prompt injection, web app vulnerabilities).
Generate Python code that:
- Uses 'boto3' to add AWS WAF managed rule groups blocking the attack pattern
- OR generates ModSecurity rules written to /etc/modsecurity/rules/custom.conf
- OR applies application-layer input validation patches
- Focus on application-layer controls, NOT network-layer or host-layer ones.
"""

    # ── BUILD THE FINAL PROMPT ──────────────────────────────────
    system_prompt = f"""You are the VigilOps Lead Security Engineer.
Based on the Security Audit below, write a complete executable Python script to remediate the threats.

SECURITY AUDIT:
{master_audit}

DETECTED ATTACK DOMAIN: {domain}

DOMAIN-SPECIFIC INSTRUCTIONS:
{domain_instructions}

OUTPUT RULES:
1. Output ONLY valid raw Python code. No markdown fences (```python). No prose. No explanation.
2. The script must address the EXACT remediation described in the audit's [REMEDIATION PATCH] section.
3. Use placeholders like 'ATTACKER_IP', 'API_KEY' so a human reviewer must fill them before execution.
4. Match the remediation domain to the attack domain. Do not generate network code for host attacks.
"""

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model":       "gpt-3.5-turbo",
        "messages":    [{"role": "user", "content": system_prompt}],
        "temperature": 0.2
    }

    try:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload
        )
        if response.status_code == 200:
            response_data = response.json()
            generated_code = response_data['choices'][0]['message']['content']

            # Strip markdown if OpenAI ignored the prompt
            generated_code = generated_code.replace("```python", "").replace("```", "").strip()

            with open("generated_firewall_patch.py", "w", encoding='utf-8') as f:
                f.write(f"# Domain: {domain}\n")
                f.write(f"# Auto-generated by VigilOps Codex Engineer\n\n")
                f.write(generated_code)

            print("   [✓] SUCCESS: Remediation code generated!")
            print(f"   [📁] File saved locally as: generated_firewall_patch.py")
            print(f"   [🎯] Patch domain tag: {domain}")
            print("\n[🚨] HITL REVIEW REQUIRED: Open 'generated_firewall_patch.py' to review the code before execution.")
        else:
            print(f"   [!] OpenAI API Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"   [!] Connection Error: {e}")


# Allows standalone testing of Codex
if __name__ == "__main__":
    test_audit = (
        "Test Audit: Successful sudo to ROOT executed. "
        "Privilege escalation detected on Linux host. NIST 800-53 Access Control."
    )
    generate_patch(test_audit)