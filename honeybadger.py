import os
import sys
import subprocess
import argparse
import time
import chromadb
import openai
from build_red_brain import build_offensive_database

AUTO_MODE = False
pcap_process = None

# 👇 PASTE YOUR REAL OPENAI API KEY HERE 👇
OPENAI_API_KEY = "YOUR_OPENAI_API_KEY_HERE"
client_ai = openai.OpenAI(api_key=OPENAI_API_KEY)


def run_nmap_scan(target_ip):
    print(f"\n[🔍] PHASE 1: Executing Nmap Recon on {target_ip}...")
    windows_nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"

    try:
        # Attempt 1: Try running it normally
        result = subprocess.run(
            ['nmap', '-p', '21,22,445,5000', '-sV', target_ip],
            capture_output=True, text=True, timeout=30
        )
        print("   [+] Nmap Scan Complete.")
        return result.stdout
    except FileNotFoundError:
        try:
            # Attempt 2: Override PATH and point directly to the executable
            print("   [*] Standard PATH failed. Attempting direct Windows execution...")
            result = subprocess.run(
                [windows_nmap_path, '-p', '21,22,445,5000', '-sV', target_ip],
                capture_output=True, text=True, timeout=30
            )
            print("   [+] Nmap Scan Complete.")
            return result.stdout
        except FileNotFoundError:
            print("[!] FATAL: Nmap was not found at the default Windows location.")
            print("    Please verify Nmap is installed in C:\\Program Files (x86)\\Nmap")
            sys.exit(1)


def query_red_brain(nmap_output, scope):
    print(f"\n[🧠] PHASE 2: Querying {scope.upper()} RAG Brain for Tradecraft...")
    try:
        client = chromadb.PersistentClient(path="./red_brain_db")
        collection = client.get_collection(name=f"playbooks_{scope}")

        results = collection.query(
            query_texts=[nmap_output],
            n_results=2
        )

        if results['documents'][0]:
            raw_intel = "\n".join(results['documents'][0])

            MAX_CONTEXT_LENGTH = 1500

            if len(raw_intel) > MAX_CONTEXT_LENGTH:
                print(
                    f"   [!] Intel payload massive ({len(raw_intel)} chars). Splicing context to prevent LLM hallucination...")
                tactical_context = raw_intel[:MAX_CONTEXT_LENGTH] + "\n\n[...TRUNCATED FOR CONTEXT LIMITS...]"
            else:
                tactical_context = raw_intel
                print("   [+] Successfully extracted and formatted relevant exploits.")

            return tactical_context
        else:
            print("   [-] No matching playbooks found in database.")
            return "No specific playbook found. Default to web fuzzing."

    except Exception as e:
        print(f"   [!] Error accessing Red Brain: {e}")
        return "Database offline. Proceed with basic recon."


def execute_command(command):
    """Executes a terminal command safely."""
    print(f"\n[⚠️] HoneyBadger requests to execute:\n    > {command}")

    global AUTO_MODE
    if not AUTO_MODE:
        approval = input("   [?] Allow execution? (y/n): ").strip().lower()
        if approval != 'y':
            return "Command execution DENIED by Security Architect."
    else:
        print("   [⚡] AUTO-FIRE ENABLED. Executing...")
        time.sleep(2)

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
        output = result.stdout if result.stdout else result.stderr
        return output[:1500]
    except Exception as e:
        return f"Error executing command: {e}"


def start_packet_capture(target_ip):
    global pcap_process
    print("\n[📡] INITIALIZING TELEMETRY EXHAUST (PCAP)...")

    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    pcap_filename = "siege_exhaust.pcap"

    # 👇 THE FIX: Set your specific VirtualBox interface number here 👇
    interface_number = "11"  # <--- REPLACE THIS WITH YOUR MAGIC NUMBER (e.g., "11" or "13")

    try:
        pcap_process = subprocess.Popen(
            [tshark_path, '-i', interface_number, '-f', f'host {target_ip}', '-w', pcap_filename],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(f"   [+] Background capture started on Interface {interface_number}. Saving to: {pcap_filename}")
    except FileNotFoundError:
        print("   [!] Wireshark (tshark.exe) not found at default location.")
        print("   [!] PCAP generation bypassed. Proceeding with siege...")


def stop_packet_capture():
    global pcap_process
    if pcap_process:
        print("\n[📡] SECURING TELEMETRY EXHAUST...")
        pcap_process.terminate()
        time.sleep(1)
        print("   [+] PCAP successfully saved to disk: siege_exhaust.pcap")


def launch_siege(target_ip, scope):
    print("==================================================")
    print(f"🦡 HONEYBADGER 3.0: AUTONOMOUS {scope.upper()} APT ONLINE 🦡")
    print("==================================================")

    start_packet_capture(target_ip)

    print("\n[🧠] PHASE 0: Bootstrapping Offensive RAG Brain...")
    build_offensive_database()

    nmap_results = run_nmap_scan(target_ip)
    tactical_context = query_red_brain(nmap_results, scope)

    print("\n[⚔️] PHASE 3: Initializing Autonomous Attack Loop...")

    system_prompt = f"""You are HONEYBADGER 3.0, an autonomous Advanced Persistent Threat (APT).
Your objective is to breach the target environment, establish persistence, and execute post-exploitation objectives.

[🎯 TARGET RECONNAISSANCE]
{nmap_results}

[🧠 TACTICAL TRADECRAFT]
{tactical_context}

[🧰 AVAILABLE WEAPONRY]
You are executing commands from a Windows Command Prompt. You are explicitly authorized to use the following arsenal:
1. 'nmap' - For deep-dive vulnerability scanning and service enumeration.
2. 'curl' - For web exploitation, API attacks, and Prompt Injection. (CRITICAL: You MUST use double quotes for JSON payloads on Windows).
3. 'ssh' & 'scp' - For brute-forcing credentials, lateral movement, and data exfiltration.
4. 'powershell' - For advanced scripting, encoding, and bypassing basic restrictions.
5. Standard Windows binaries ('ping', 'whoami', 'netstat', 'ipconfig').
6. 'python tools/sqlmap/sqlmap.py' - For automated SQL injection and database enumeration.

[⚠️ RULES OF ENGAGEMENT]
1. Analyze the Target Reconnaissance against the Tactical Tradecraft.
2. Select the appropriate weapon from your Available Weaponry.
3. To execute a command, you MUST output ONLY in this exact format:
RUN_COMMAND: <your terminal command>
4. Wait for the terminal output. Base your next move on that output.
5. Once you have successfully exploited the target, established persistence, or gathered enough intel, summarize your findings using:
REPORT: <your summary>
"""

    messages = [
        {"role": "system", "content": system_prompt}
    ]

    for step in range(5):
        print(f"\n[🦡] Cycle {step + 1} | HoneyBadger is thinking...")

        ai_output = ""

        try:
            response = client_ai.chat.completions.create(
                model="gpt-4o-mini",
                messages=messages,
                temperature=0.7
            )
            ai_output = response.choices[0].message.content.strip()

            if "RUN_COMMAND:" in ai_output:
                command = ai_output.split("RUN_COMMAND:")[1].split('\n')[0].strip()
                terminal_output = execute_command(command)

                print(f"   [🖥️] Terminal Output:\n{terminal_output.strip()}")

                messages.append({"role": "assistant", "content": ai_output})
                messages.append({"role": "user", "content": f"TERMINAL OUTPUT:\n{terminal_output}"})


            elif "REPORT:" in ai_output:
                print("\n==================================================")
                print(f"[🔥] FINAL SIEGE REPORT:\n{ai_output}")
                print("==================================================")
                break
            else:
                messages.append({"role": "assistant", "content": ai_output})
                messages.append(
                    {"role": "user", "content": "Command format invalid. Use RUN_COMMAND: or REPORT: format."})

        except Exception as e:
            print(f"[!] Critical Engine Error: {e}")
            break

        if step == 4 and "REPORT:" not in ai_output:
            print("\n==================================================")
            print(
                "[🔥] FINAL SIEGE REPORT:\nMax attack cycles reached (5/5). Target resisted initial breach attempts. Recommending manual analyst review.")
            print("==================================================")

    # Fixed Indentation: Now correctly aligned inside launch_siege, outside the for loop
    stop_packet_capture()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HoneyBadger 3.0 - Autonomous Red Team")
    parser.add_argument("--target", required=True, help="The target IP address")
    parser.add_argument("--auto", action="store_true", help="Run without manual prompts")
    parser.add_argument("--scope", required=True, choices=['infra', 'genai'], help="Engagement Scope")
    args = parser.parse_args()

    AUTO_MODE = args.auto

    launch_siege(args.target, args.scope)