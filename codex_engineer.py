import requests
import json

# ---------------------------------------------------------
# VIGILOPS V3: CODEX ENGINEER (OPENAI)
# Purpose: Receives the Master Audit from the Orchestrator
# and dynamically writes the Python remediation patch.
# ---------------------------------------------------------

# 👇 PASTE YOUR REAL OPENAI API KEY HERE 👇
OPENAI_API_KEY = "YOUR_OPENAI_API_KEY_HERE"


def generate_patch(master_audit):
    print("\n[🤖] Waking up Codex Engineer (OpenAI)...")
    print("   [⚙️] Translating Master Audit into executable Python code...")

    if OPENAI_API_KEY == "YOUR_OPENAI_API_KEY_HERE":
        print("   [!] ERROR: You forgot to add your OpenAI API Key in codex_engineer.py!")
        return

    system_prompt = f"""You are the VigilOps Lead Security Engineer.
Based on the following Security Audit, write a complete, executable Python script to remediate the threats.

SECURITY AUDIT:
{master_audit}

INSTRUCTIONS:
1. If the audit mentions Palo Alto, write a script using the 'requests' library to interact with the Palo Alto REST API to block the attacking IP.
2. If the audit mentions AWS WAF, write a script using 'boto3' to update the WAF IPSet to block the IP.
3. OUTPUT ONLY VALID PYTHON CODE. Do not use markdown formatting (like ```python). No explanations. Just raw code.
"""

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "gpt-3.5-turbo",  # You can change to gpt-4o if you have access
        "messages": [{"role": "user", "content": system_prompt}],
        "temperature": 0.2
    }

    try:
        response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)

        if response.status_code == 200:
            response_data = response.json()
            generated_code = response_data['choices'][0]['message']['content']

            # Clean up markdown formatting if OpenAI ignores the prompt instructions
            generated_code = generated_code.replace("```python", "").replace("```", "").strip()

            with open("generated_firewall_patch.py", "w", encoding='utf-8') as f:
                f.write(generated_code)

            print("   [✓] SUCCESS: Remediation code generated!")
            print("   [📁] File saved locally as: generated_firewall_patch.py")
            print("\n[🚨] HITL REVIEW REQUIRED: Open 'generated_firewall_patch.py' to review the code before execution.")
        else:
            print(f"   [!] OpenAI API Error: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"   [!] Connection Error: {e}")


# This allows you to test Codex by itself if needed
if __name__ == "__main__":
    test_audit = "Test Audit: Block IP 192.168.1.50 on Palo Alto."
    generate_patch(test_audit)