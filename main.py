import os
import sys
import random
import requests


# ── ADVERSARY SIMULATION MODULE CONFIG ─────────────────────────────
UBUNTU_VM_IP = "192.168.56.104"
UBUNTU_USER  = "wazuhub"
SPOOF_FILE   = "/home/wazuhub/spoof_ip.txt"


def fetch_live_threat_intel():
    print("   [📡] Reaching out to Global Threat Intel Feeds (abuse.ch)...")
    try:
        url      = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
        response = requests.get(url, timeout=8)
        if response.status_code == 200:
            ips = []
            for line in response.text.splitlines():
                if not line.startswith("#") and line.strip():
                    parts = line.split(",")
                    if len(parts) >= 2:
                        ip = parts[1].strip().strip('"')
                        if ip.count(".") == 3:
                            ips.append(ip)
            if len(ips) >= 3:
                selected = random.sample(ips, 3)
                print(f"   [✓] Live feed loaded — {len(ips)} active C2 nodes indexed.")
                return selected
    except Exception as e:
        print(f"   [!] Live feed unreachable ({e}). Using fallback cache...")
    fallback = ["45.133.1.53", "185.153.196.22", "193.169.255.44"]
    print("   [✓] Fallback threat intel cache loaded.")
    return fallback


def push_spoof_ip(spoof_ip: str):
    cmd    = f'ssh {UBUNTU_USER}@{UBUNTU_VM_IP} "echo {spoof_ip} > {SPOOF_FILE}"'
    result = os.system(cmd)
    if result == 0:
        print(f"   [✓] Threat actor profile ({spoof_ip}) pushed to Wazuh MCP.")
    else:
        print(f"   [!] SSH push failed.")


def clear_spoof_ip():
    os.system(f'ssh {UBUNTU_USER}@{UBUNTU_VM_IP} "rm -f {SPOOF_FILE}"')
    print("   [✓] Adversary simulation cleared.")


# ── MENU HELPERS ───────────────────────────────────────────────────

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    banner = """
    ===================================================================
     🛡️  V.I.G.I.L. O.P.S.  v4.0 - UNIFIED AI-SOAR & OFFENSIVE PLATFORM 🛡️
    ===================================================================
    """
    print(banner)


# ── MAIN MENU ──────────────────────────────────────────────────────

def main_menu():
    while True:
        clear_screen()
        print_banner()
        print("  [1] 📡 Initialize Data Diode (Fetch Live Threat Intel)")
        print("  [2] 🕵️  Run Client Recon Agent (Gather Local System Intel)")
        print("  [3] 🧠 Build Dual-Segment RAG Brain (Client + Global DB)")
        print("  [4] 🎯 Deploy Local Honeypot (Vulnerable Target)")
        print("  [5] 🦡 Launch Autonomous Red Team (HoneyBadger Siege)")
        print("  [6] ⚡ Engage AI-SOAR Pipeline (DeepSeek Orchestrator)")
        print("  [7] 📄 Run Universal PDF Ripper (Data Ingestion)")
        print("  [8] 🏴 Launch CTF Solver (HoneyBadger CTF Mode)")
        print("  [0] 🚪 Exit System\n")

        choice = input("VIGILOPS_CMD> ")

        if choice == '1':
            print("\n[*] Initializing Threat Intel Scraper...")
            os.system(f'"{sys.executable}" threat_intel_scraper.py')
            input("\nPress Enter to return to Command Center...")

        elif choice == '2':
            print("\n[*] Running Local System Reconnaissance...")
            os.system(f'"{sys.executable}" recon_agent.py')
            input("\nPress Enter to return to Command Center...")

        elif choice == '3':
            print("\n[*] Initializing RAG Builder...")
            os.system(f'"{sys.executable}" rag_builder_v3.py')
            input("\nPress Enter to return to Command Center...")

        elif choice == '4':
            print("\n[*] Deploying Honeypot.")
            os.system(f'start "" "{sys.executable}" vulnerable_app.py')
            print("   [✓] Honeypot launched in a new terminal window.")
            input("\nPress Enter to return to Command Center...")

        elif choice == '5':
            print("\n[*] Unleashing HoneyBadger...")
            target_ip = input("   [>] Enter Target IP: ").strip()

            print("   [>] Select Engagement Scope:")
            print("       [1] Traditional Infrastructure (CPTS)")
            print("       [2] Generative AI API (ATLAS)")
            scope_choice = input("   [>] Choice (1/2): ").strip()

            scope_arg = "infra" if scope_choice == '1' else "genai"
            auto_mode = input("   [>] Enable Auto-Fire Mode? (y/n): ").strip().lower()
            auto_flag = "--auto" if auto_mode == 'y' else ""

            if not target_ip:
                print("   [!] Aborted: Target IP required.")
                input("\nPress Enter to return to Command Center...")
                continue

            # ── ADVERSARY SIMULATION MODULE ────────────────────────
            print("\n   ╔══════════════════════════════════════════╗")
            print("   ║  🎭  ADVERSARY SIMULATION MODULE          ║")
            print("   ╠══════════════════════════════════════════╣")
            print("   ║  Inject real threat actor IP into SIEM   ║")
            print("   ║  Forces VT + Shodan to profile live C2s  ║")
            print("   ╚══════════════════════════════════════════╝\n")

            live_ips = fetch_live_threat_intel()

            print(f"   [?] Select attacker profile for SIEM injection:")
            print(f"       [1] 🔴 {live_ips[0]}  (Live Botnet / C2 Node)")
            print(f"       [2] 🔴 {live_ips[1]}  (Live Botnet / C2 Node)")
            print(f"       [3] 🔴 {live_ips[2]}  (Live Botnet / C2 Node)")
            print(f"       [4] ✏️  Enter a manual IP address")
            print(f"       [0] ✅  No mask — use actual local IP\n")

            mask_choice = input("   [>] Choice (0-4): ").strip()

            spoof_ip = ""
            if mask_choice == '1':
                spoof_ip = live_ips[0]
            elif mask_choice == '2':
                spoof_ip = live_ips[1]
            elif mask_choice == '3':
                spoof_ip = live_ips[2]
            elif mask_choice == '4':
                spoof_ip = input("   [>] Enter manual threat actor IP: ").strip()

            if spoof_ip:
                print(f"\n   [🎭] Activating adversary simulation: {spoof_ip}")
                push_spoof_ip(spoof_ip)
            else:
                print(f"\n   [✅] Real IP mode. Clearing previous simulation state...")
                clear_spoof_ip()

            print("   [⚡] Safety limits OFF. Autonomous siege engaged.")
            os.system(f'"{sys.executable}" honeybadger.py --target {target_ip} {auto_flag} --scope {scope_arg}')

        elif choice == '6':
            print("\n[*] Engaging AI-SOAR Pipeline...")
            print("   [⚡] Waking up the Agentic Orchestrator (DeepSeek-R1)...")
            os.system(f'"{sys.executable}" agentic_orchestrator.py')
            input("\nPress Enter to return to Command Center...")

        elif choice == '7':
            print("\n[*] Initializing Universal PDF Ripper...")
            os.system(f'"{sys.executable}" pdf_ripper.py')
            input("\nPress Enter to return to Command Center...")

        elif choice == '8':
            # ── CTF SOLVER ─────────────────────────────────────────
            print("\n╔══════════════════════════════════════════════════╗")
            print("║  🏴  HONEYBADGER CTF SOLVER — AUTONOMOUS MODE     ║")
            print("╠══════════════════════════════════════════════════╣")
            print("║  Kali Attack Node: 192.168.56.106                 ║")
            print("║  State Machine: RECON→ANALYZE→EXECUTE→FLAG       ║")
            print("╚══════════════════════════════════════════════════╝\n")

            # Collect challenge info
            target = input("   [>] Target IP or URL: ").strip()
            if not target:
                print("   [!] Aborted: Target required.")
                input("\nPress Enter to return to Command Center...")
                continue

            challenge_name = input("   [>] Challenge name (e.g. 'Simple CTF'): ").strip() or "Unknown Challenge"
            challenge_desc = input("   [>] Challenge description (optional): ").strip() or "Find the flag."

            print("   [>] Select platform:")
            print("       [1] HackTheBox (HTB{...})")
            print("       [2] TryHackMe  (THM{...})")
            print("       [3] PicoCTF    (picoCTF{...})")
            print("       [4] Generic    (flag{...})")
            platform_choice = input("   [>] Choice (1-4): ").strip()

            platforms = {'1': 'htb', '2': 'thm', '3': 'picoctf', '4': 'generic'}
            platform  = platforms.get(platform_choice, 'htb')

            custom_flag = input("   [>] Custom flag format regex (or Enter to use platform default): ").strip()

            auto_mode = input("   [>] Enable Auto-Fire Mode? (y/n): ").strip().lower()
            auto      = auto_mode == 'y'

            if auto:
                print("   [⚡] Auto-fire mode ON. Full autonomous solving engaged.")
            else:
                print("   [👤] Manual approval mode. You'll confirm each tool call.")

            # Launch CTF engine
            from ctf_engine import launch_ctf_siege
            flag = launch_ctf_siege(
                target=target,
                challenge_name=challenge_name,
                challenge_desc=challenge_desc,
                platform=platform,
                flag_format=custom_flag,
                auto_mode=auto
            )

            if flag:
                print(f"\n   🚩 FLAG: {flag}")
            else:
                print("\n   ❌ Challenge not solved this siege. Check lessons_learned.txt for next attempt.")

            input("\nPress Enter to return to Command Center...")

        elif choice == '0':
            print("\nShutting down VigilOps. Stay secure.")
            break

        else:
            print("\n[!] Invalid command.")
            input("Press Enter to retry...")


if __name__ == "__main__":
    main_menu()