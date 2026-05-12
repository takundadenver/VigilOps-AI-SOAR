import psutil
import platform
import socket
import os
import requests
import subprocess
from datetime import datetime


# ---------------------------------------------------------
# VIGILOPS V3: ADVANCED FORWARD-DEPLOYED RECON AGENT
# Purpose: Scrape host telemetry, OS logs, SOPs, and aggregate
# Multi-SIEM data (Wazuh, Splunk, Elastic) into a unified report.
# ---------------------------------------------------------

def get_system_and_network():
    """Gathers hardware, OS, and active network ports."""
    print("[*] Scraping System & Network Specifications...")
    open_ports = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                open_ports.append(f"Port: {conn.laddr.port} | Protocol: {conn.type.name}")
    except psutil.AccessDenied:
        open_ports.append("WARNING: Access Denied. Run as Admin for full port scan.")

    return {
        "OS": platform.system(),
        "Hostname": socket.gethostname(),
        "RAM_Usage_Percent": psutil.virtual_memory().percent,
        "Listening_Ports": open_ports[:10]  # Cap at 10 for AI context limits
    }


def scrape_os_logs():
    """Scrapes raw OS-level security logs (Windows Event Logs or Linux Auth logs)."""
    print("[*] Scraping native OS security logs...")
    os_logs = []
    current_os = platform.system()

    try:
        if current_os == "Windows":
            # Safely grab the last 3 critical Application errors using PowerShell
            cmd = 'powershell -Command "Get-EventLog -LogName Application -Newest 3 -EntryType Error | Select-Object -ExpandProperty Message"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            if result.stdout:
                os_logs.extend(result.stdout.strip().split('\n'))
            else:
                os_logs.append("No recent critical OS events found.")
        else:
            # Linux fallback
            os_logs.append("Linux OS detected. /var/log/auth.log parsing bypassed for this demo.")
    except Exception as e:
        os_logs.append(f"Failed to scrape OS logs: {e}")

    return os_logs


def aggregate_siem_logs():
    """
    Probes multiple Enterprise SIEMs (Wazuh, Splunk, Elastic).
    Falls back to local application logs if all network SIEMs are unreachable.
    """
    print("[*] Aggregating telemetry across Enterprise SIEMs...")
    siem_data = {
        "Wazuh_Alerts": [],
        "Splunk_Events": [],
        "Elastic_Logs": [],
        "Local_Fallback": []
    }

    # 1. Probe Wazuh
    try:
        requests.get("https://127.0.0.1:55000", verify=False, timeout=1)
        siem_data["Wazuh_Alerts"].append("[CONNECTED] Wazuh API active.")
    except:
        siem_data["Wazuh_Alerts"].append("[OFFLINE] Wazuh API unreachable.")

    # 2. Probe Splunk (Default Mgmt Port 8089)
    try:
        requests.get("https://127.0.0.1:8089", verify=False, timeout=1)
        siem_data["Splunk_Events"].append("[CONNECTED] Splunk API active.")
    except:
        siem_data["Splunk_Events"].append("[OFFLINE] Splunk API unreachable.")

    # 3. Probe ElasticSearch (Default Port 9200)
    try:
        requests.get("http://127.0.0.1:9200", timeout=1)
        siem_data["Elastic_Logs"].append("[CONNECTED] ElasticSearch active.")
    except:
        siem_data["Elastic_Logs"].append("[OFFLINE] ElasticSearch unreachable.")

    # 4. Local Log Fallback (If SIEMs fail, grab the honeypot logs)
    fallback_log = "app_security_logs.txt"
    if os.path.exists(fallback_log):
        with open(fallback_log, 'r') as f:
            lines = f.readlines()
            # Grab last 3 attack payloads
            attacks = [line.strip() for line in lines if "USER_INPUT:" in line][-3:]
            siem_data["Local_Fallback"] = attacks if attacks else ["No local attacks logged."]

    return siem_data


def gather_local_sops():
    """Scoops up all Corporate SOPs so the AI knows the rules of engagement."""
    print("[*] Gathering Corporate Policies and SOPs...")
    sop_content = []
    kb_path = "vigil_knowledge_base"

    if os.path.exists(kb_path):
        for filename in os.listdir(kb_path):
            if filename.endswith(".txt"):
                with open(os.path.join(kb_path, filename), 'r', encoding='utf-8') as f:
                    # Append file name and its contents
                    sop_content.append(f"--- {filename} ---\n{f.read().strip()}")
    else:
        sop_content.append("WARNING: No vigil_knowledge_base folder found on host.")

    return sop_content


def generate_rag_report():
    """Compiles all scraped intel into the master Unified Report."""
    print("\n[+] Compiling VigilOps Unified Intel Report...")

    report_data = {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "System_Intel": get_system_and_network(),
        "OS_Logs": scrape_os_logs(),
        "SIEM_Intel": aggregate_siem_logs(),
        "Corporate_SOPs": gather_local_sops()
    }

    report_text = f"=== VIGILOPS V3 UNIFIED RECONNAISSANCE REPORT ===\n"
    report_text += f"Scan Time: {report_data['Timestamp']}\n\n"

    report_text += "[1. SYSTEM & NETWORK POSTURE]\n"
    for key, value in report_data['System_Intel'].items():
        if isinstance(value, list):
            report_text += f"- {key}:\n"
            for item in value: report_text += f"  > {item}\n"
        else:
            report_text += f"- {key}: {value}\n"

    report_text += "\n[2. HOST OS SECURITY LOGS]\n"
    for log in report_data['OS_Logs']:
        report_text += f"- {log}\n"

    report_text += "\n[3. SIEM AGGREGATION (Wazuh/Splunk/Elastic)]\n"
    for siem, logs in report_data['SIEM_Intel'].items():
        report_text += f"- {siem}:\n"
        for log in logs: report_text += f"  > {log}\n"

    report_text += "\n[4. LOCAL CORPORATE SOPs & POLICIES]\n"
    for sop in report_data['Corporate_SOPs']:
        report_text += f"{sop}\n\n"

    # Save to file
    file_name = "unified_client_intel.txt"
    with open(file_name, "w", encoding='utf-8') as f:
        f.write(report_text)

    print(f"\n[✓] Recon complete. Data aggregated and saved to {file_name}")
    print("--------------------------------------------------")
    print(report_text[:500] + "\n... [TRUNCATED FOR DISPLAY] ...")


if __name__ == "__main__":
    import urllib3

    urllib3.disable_warnings()
    generate_rag_report()