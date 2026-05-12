import os
import sys


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    banner = """
    ===================================================================
     🛡️  V.I.G.I.L. O.P.S.  v3.0 - UNIFIED AI-SOAR & OFFENSIVE PLATFORM 🛡️
    ===================================================================
    """
    print(banner)


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
            print("\n[*] Deploying Honeypot. (NOTE: This blocks the terminal. Press Ctrl+C to stop it).")
            os.system(f'start "" "{sys.executable}" vulnerable_app.py')
            print("   [✓] Honeypot launched in a new terminal window.")
            input("\nPress Enter to return to Command Center...")




        elif choice == '5':

            print("\n[*] Unleashing HoneyBadger...")

            target_ip = input("   [>] Enter Target IP (e.g., your Ubuntu VM IP): ").strip()

            # 👇 NEW: The Engagement Scoping Prompt 👇

            print("   [>] Select Engagement Scope:")

            print("       [1] Traditional Infrastructure (CPTS)")

            print("       [2] Generative AI API (ATLAS)")

            scope_choice = input("   [>] Choice (1/2): ").strip()

            scope_arg = "infra" if scope_choice == '1' else "genai"

            auto_mode = input("   [>] Enable Auto-Fire Mode? (y/n): ").strip().lower()

            auto_flag = "--auto" if auto_mode == 'y' else ""

            if target_ip:

                print("   [⚡] Safety limits OFF. Autonomous siege engaged.")

                # Pass the scope argument into the command

                os.system(f'"{sys.executable}" honeybadger.py --target {target_ip} {auto_flag} --scope {scope_arg}')

            else:

                print("   [!] Aborted: Target IP required.")


        elif choice == '6':

            print("\n[*] Engaging AI-SOAR Pipeline...")

            vm_ip = input("   [>] Enter the Target VM IP to pull logs from: ").strip()

            if vm_ip:

                print("\n   [📥] Fetching live incident logs from VM via Secure Copy (SCP)...")

                print("   (You may be asked to enter the VM's password: password123)")

                # Use Windows built-in SCP to securely pull the file from the VM

                # Format: scp user@ip:/remote/path/to/file ./local_destination

              #  os.system(
            #     f"scp administrator@{vm_ip}:/home/administrator/ai_honeypot/app_security_logs.txt ./app_security_logs.txt")

                print("   [✓] Telemetry successfully bridged to the Command Center!")

                print("\n[*] Waking up the Agentic Orchestrator (DeepSeek-R1)...")

                # Now that the file is local, run the orchestrator as normal

                os.system(f'"{sys.executable}" agentic_orchestrator.py')

            else:

                print("   [!] Pipeline aborted: No VM IP provided.")

            input("\nPress Enter to return to Command Center...")

        elif choice == '0':
            print("\nShutting down VigilOps. Stay secure.")
            break
        else:
            print("\n[!] Invalid command.")
            input("Press Enter to retry...")


if __name__ == "__main__":
    main_menu()