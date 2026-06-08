# VigilOps V4.0 — Lab Setup Guide
## Complete 5-Node VirtualBox Deployment

---

## Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 16 GB | 32 GB |
| CPU | 4 cores | 8 cores |
| Disk | 200 GB free | 500 GB SSD |
| OS | Windows 10 | Windows 11 |
| VirtualBox | 7.0+ | 7.1+ |

---

## Network Architecture

All VMs use a **Host-Only Network** adapter on the `192.168.56.0/24` subnet.

```
Windows Host (Red Team)     192.168.56.1    ← automatically assigned
Metasploitable3 (Infra)     192.168.56.102
LLMGoat Ubuntu (GenAI)      192.168.56.105
Wazuh Ubuntu (Blue Team)    192.168.56.104
Kali Linux (Attack Node)    192.168.56.106
```

### VirtualBox Host-Only Network Setup

1. Open VirtualBox → **File → Host Network Manager**
2. Create adapter `vboxnet0` (or use existing)
3. Set IPv4 Address: `192.168.56.1`
4. Set IPv4 Network Mask: `255.255.255.0`
5. **Disable DHCP server** (we assign static IPs manually)

---

## Node 1 — Red Team (Windows Host)

This is your existing Windows machine. No VM needed.

### Prerequisites

```powershell
# Python 3.13
winget install Python.Python.3.13

# Install VigilOps dependencies
cd C:\VigilOps_2\ai_target
pip install -r requirements.txt

# Metasploit (for MetasploitMCP)
# Download: https://metasploit.com/download
# Enable RPC: msfconsole → load msgrpc Pass=msf123 ServerPort=55553

# Ollama (for local DeepSeek-R1)
winget install Ollama.Ollama
ollama pull deepseek-r1:14b
```

### Configure API Keys

Edit `honeybadger.py` and `agentic_orchestrator.py`:

```python
DEEPSEEK_API_KEY = "your-key-here"   # https://platform.deepseek.com
VT_API_KEY       = "your-key-here"   # https://virustotal.com
SHODAN_API_KEY   = "your-key-here"   # https://account.shodan.io
```

### Passwordless SSH Setup (required for all VMs)

```powershell
# Generate key if not exists
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\id_ed25519

# Copy to each VM (run for each IP)
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh user@192.168.56.xxx "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

---

## Node 2 — Infra Target (Metasploitable3)

### Download and Import

1. Download Metasploitable3 OVA from: https://github.com/rapid7/metasploitable3
2. VirtualBox → **File → Import Appliance** → select `.ova`
3. Set network adapter to **Host-Only (vboxnet0)**
4. Boot and configure static IP:

```bash
sudo nano /etc/network/interfaces
# Add:
auto eth1
iface eth1 inet static
  address 192.168.56.102
  netmask 255.255.255.0
```

### Install Wazuh Agent

```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb
sudo WAZUH_MANAGER='192.168.56.104' dpkg -i wazuh-agent_4.7.5-1_amd64.deb
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

### Verify Services Running

```bash
sudo service proftpd status    # FTP on port 21
sudo service apache2 status    # HTTP on port 80
sudo service ssh status        # SSH on port 22
```

---

## Node 3 — GenAI Target (LLMGoat)

### VM Specs

- **OS:** Ubuntu 22.04 LTS
- **RAM:** 4 GB minimum (model loads ~3.5 GB)
- **Disk:** 20 GB
- **IP:** 192.168.56.105

### Ubuntu Install

1. Download Ubuntu 22.04 Server ISO
2. Create new VM: 4 GB RAM, 20 GB disk, Host-Only network
3. Install Ubuntu, create user `llmgoat` with password `llmgoat`
4. Set static IP in `/etc/netplan/00-installer-config.yaml`:

```yaml
network:
  version: 2
  ethernets:
    enp0s8:
      addresses: [192.168.56.105/24]
      nameservers:
        addresses: [8.8.8.8]
```

```bash
sudo netplan apply
```

### Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker llmgoat
newgrp docker
```

### Deploy LLMGoat

```bash
git clone https://github.com/Snyk/LLMGoat.git ~/LLMGoat
cd ~/LLMGoat

# Edit compose.github.yaml — set LLMGOAT_VERBOSE=1
nano compose.github.yaml

# Start container
docker compose -f compose.github.yaml up llmgoat-cpu -d
docker logs llmgoat-cpu --tail 5
```

Wait ~2 minutes for Gemma-2-9B to load. Verify: `curl http://192.168.56.105:5000`

### Log Extractor Service (Wazuh integration)

```bash
# Get the container log path
docker inspect llmgoat-cpu --format='{{.LogPath}}'

# Create extractor script (replace CONTAINER_ID with your actual ID)
sudo tee /usr/local/bin/llmgoat-log-extractor.sh << 'EOF'
#!/bin/bash
DOCKER_LOG="/var/lib/docker/containers/CONTAINER_ID/CONTAINER_ID-json.log"
OUTPUT="/var/log/llmgoat-access.log"
tail -n 0 -f "$DOCKER_LOG" | while IFS= read -r line; do
    if echo "$line" | grep -q "FLASK"; then
        TIMESTAMP=$(date '+%b %d %H:%M:%S')
        ENDPOINT=$(echo "$line" | grep -oP '/api/[^\\]+' | head -1)
        SRCIP=$(echo "$line" | grep -oP 'from \K[\d.]+' | head -1)
        METHOD=$(echo "$line" | grep -oP '(POST|GET)' | head -1)
        echo "$TIMESTAMP llmgoat-target llmgoat: $METHOD $ENDPOINT from $SRCIP" >> "$OUTPUT"
    fi
done
EOF

sudo chmod +x /usr/local/bin/llmgoat-log-extractor.sh

sudo tee /etc/systemd/system/llmgoat-log-extractor.service << 'EOF'
[Unit]
Description=LLMGoat Log Extractor for Wazuh
After=docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/llmgoat-log-extractor.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable llmgoat-log-extractor.service
sudo systemctl start llmgoat-log-extractor.service
```

### Install Wazuh Agent

```bash
# Fix Docker log permissions first
sudo chmod -R o+rX /var/lib/docker/containers/
sudo chmod o+x /var/lib/docker/

wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb
sudo WAZUH_MANAGER='192.168.56.104' dpkg -i wazuh-agent_4.7.5-1_amd64.deb

# Add Docker log collection to ossec.conf
# Edit /var/ossec/etc/ossec.conf — add before </ossec_config>:
# <localfile>
#   <log_format>syslog</log_format>
#   <location>/var/log/llmgoat-access.log</location>
# </localfile>

sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

---

## Node 4 — Blue Team Intel (Wazuh Manager)

### VM Specs

- **OS:** Ubuntu 22.04 LTS
- **RAM:** 6 GB minimum
- **Disk:** 50 GB
- **IP:** 192.168.56.104
- **User:** wazuhub

### Install Wazuh All-in-One

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml
# Edit config.yml — set node IP to 192.168.56.104
sudo bash wazuh-install.sh -a
```

Note the generated admin password or set manually:
```bash
# Change dashboard password
sudo /usr/share/wazuh-indexer/bin/indexer-security-password.sh -u admin -p VigilOps2026.
```

Access dashboard: `https://192.168.56.104` → admin / VigilOps2026.

### Enable Archives Logging

```bash
sudo nano /var/ossec/etc/ossec.conf
# Find and change:
# <logall>yes</logall>
# <logall_json>yes</logall_json>

sudo systemctl restart wazuh-manager
```

### Custom OWASP LLM Detection Rules

```bash
# Add decoders to local_decoder.xml
sudo nano /var/ossec/etc/decoders/local_decoder.xml
# Add after existing decoder:
# <decoder name="llmgoat-flask">
#   <program_name>llmgoat</program_name>
#   <regex>(\.+)\s(/api/\.+)\sfrom\s(\.+)</regex>
#   <order>method, url, srcip</order>
# </decoder>

# Create rules file
sudo tee /var/ossec/etc/rules/llmgoat_rules.xml << 'EOF'
<group name="llmgoat,llm_attack,">
  <rule id="100001" level="6">
    <decoded_as>llmgoat-flask</decoded_as>
    <description>LLMGoat: API endpoint accessed $(url)</description>
  </rule>
  <rule id="100002" level="10">
    <decoded_as>llmgoat-flask</decoded_as>
    <match>/api/a01-prompt-injection</match>
    <description>LLMGoat: OWASP-A01 Prompt Injection from $(srcip)</description>
  </rule>
  <rule id="100003" level="10">
    <decoded_as>llmgoat-flask</decoded_as>
    <match>/api/a02-sensitive-information-disclosure</match>
    <description>LLMGoat: OWASP-A02 Sensitive Info Disclosure from $(srcip)</description>
  </rule>
  <rule id="100007" level="10">
    <decoded_as>llmgoat-flask</decoded_as>
    <match>/api/a06-excessive-agency</match>
    <description>LLMGoat: OWASP-A06 Excessive Agency from $(srcip)</description>
  </rule>
  <rule id="100008" level="10">
    <decoded_as>llmgoat-flask</decoded_as>
    <match>/api/a07-system-prompt-leakage</match>
    <description>LLMGoat: OWASP-A07 System Prompt Leakage from $(srcip)</description>
  </rule>
  <rule id="100011" level="10">
    <decoded_as>llmgoat-flask</decoded_as>
    <match>/api/a10-unbounded-consumption</match>
    <description>LLMGoat: OWASP-A10 Unbounded Consumption from $(srcip)</description>
  </rule>
</group>
EOF

sudo /var/ossec/bin/wazuh-analysisd -t 2>&1  # validate — should show no errors
sudo systemctl restart wazuh-manager
```

### Deploy Blue Team MCP Servers

Copy all files from `mcp_servers/` to the VM:

```bash
scp mcp_servers/wazuh_mcp_server.py wazuhub@192.168.56.104:/home/wazuhub/
scp mcp_servers/vt_mcp_server.py wazuhub@192.168.56.104:/home/wazuhub/
scp mcp_servers/shodan_mcp_server.py wazuhub@192.168.56.104:/home/wazuhub/
scp mcp_servers/exploit_intel_mcp_server.py wazuhub@192.168.56.104:/home/wazuhub/
scp mcp_servers/nuclei_mcp_server.py wazuhub@192.168.56.104:/home/wazuhub/
```

Install dependencies on the VM:

```bash
ssh wazuhub@192.168.56.104
pip install mcp uvicorn requests --break-system-packages
```

Create systemd service for each MCP server (example for Wazuh MCP):

```bash
sudo tee /etc/systemd/system/vigilops-wazuh-mcp.service << 'EOF'
[Unit]
Description=VigilOps Wazuh MCP Server
After=network.target wazuh-manager.service

[Service]
Type=simple
User=wazuhub
ExecStart=/usr/bin/python3 /home/wazuhub/wazuh_mcp_server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable vigilops-wazuh-mcp.service
sudo systemctl start vigilops-wazuh-mcp.service
```

Repeat for ports 8001 (vt), 8002 (shodan), 8003 (exploit_intel), 8004 (nuclei).

---

## Node 5 — Kali Attack Node

### VM Setup

1. Download Kali VirtualBox OVA: https://www.kali.org/get-kali/#kali-virtual-machines
2. **File → Import Appliance** → select `.ova`
3. Set network adapter to **Host-Only (vboxnet0)**
4. Boot → login: `kali` / `kali`
5. Set static IP:

```bash
sudo nano /etc/network/interfaces
# Add:
auto eth1
iface eth1 inet static
  address 192.168.56.106
  netmask 255.255.255.0
```

### Enable SSH

```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

### Install Full Arsenal

```bash
# This takes 20-40 minutes and ~15 GB
sudo apt update && sudo apt install -y kali-linux-everything

# Additional tools
sudo apt install -y sshpass

# Unzip rockyou for password cracking
cp /usr/share/wordlists/rockyou.txt.gz /tmp/
gunzip /tmp/rockyou.txt.gz
```

### Deploy Kali Tools MCP

```bash
# Install MCP
pip install "mcp>=1.24.0" uvicorn --break-system-packages

# Copy MCP server from Windows
# (run from Windows PowerShell)
# scp mcp_servers/kali_tools_mcp.py kali@192.168.56.106:/home/kali/

# Create systemd service
sudo tee /etc/systemd/system/vigilops-kali-tools.service << 'EOF'
[Unit]
Description=VigilOps Kali Tools MCP Server
After=network.target

[Service]
Type=simple
User=kali
ExecStart=/usr/bin/python3 /home/kali/kali_tools_mcp.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable vigilops-kali-tools.service
sudo systemctl start vigilops-kali-tools.service
sudo systemctl status vigilops-kali-tools.service --no-pager | grep Active
```

### Connect to TryHackMe VPN (for CTF Mode)

```bash
# Download your .ovpn from https://tryhackme.com/access
# Copy to Kali:
# scp your-file.ovpn kali@192.168.56.106:/home/kali/thm.ovpn

sudo openvpn --config /home/kali/thm.ovpn --daemon --log /tmp/thm-vpn.log
sleep 10
ip addr show tun0  # should show 10.x.x.x
```

---

## Verification Checklist

Run from Windows PowerShell after all nodes are up:

```powershell
# Node connectivity
ping 192.168.56.102  # Metasploitable3
ping 192.168.56.104  # Wazuh
ping 192.168.56.105  # LLMGoat
ping 192.168.56.106  # Kali

# Wazuh dashboard
# Open browser: https://192.168.56.104
# Login: admin / VigilOps2026.
# Check all 3 agents show Active

# LLMGoat
curl http://192.168.56.105:5000

# MCP servers (all should return: event: endpoint)
curl http://192.168.56.104:8000/sse
curl http://192.168.56.104:8001/sse
curl http://192.168.56.104:8002/sse
curl http://192.168.56.104:8003/sse
curl http://192.168.56.104:8004/sse
curl http://192.168.56.106:8005/sse

# Full Kali MCP connectivity test
cd C:\VigilOps_2\ai_target
python3 test_kali_mcp.py  # should show 17 tools available
```

---

## Environment Variables Reference

| Variable | Where Set | Value |
|----------|-----------|-------|
| `DEEPSEEK_API_KEY` | honeybadger.py, agentic_orchestrator.py, ctf_engine.py | From platform.deepseek.com |
| `VT_API_KEY` | vt_mcp_server.py | From virustotal.com |
| `SHODAN_API_KEY` | shodan_mcp_server.py | From account.shodan.io |
| Wazuh admin password | Wazuh VM | VigilOps2026. |
| Kali SSH | All nodes | passwordless via id_ed25519 |

---

## Common Issues

**"Address already in use" on MCP port**
```bash
sudo pkill -f "mcp_server"
sudo fuser -k PORT/tcp
sudo systemctl restart vigilops-SERVICE.service
```

**Wazuh agent shows Disconnected**
```bash
sudo systemctl restart wazuh-agent    # on target VM
sudo systemctl restart wazuh-manager  # on Wazuh VM
```

**LLMGoat container stopped after host reboot**
```bash
ssh llmgoat@192.168.56.105
cd ~/LLMGoat && docker compose -f compose.github.yaml up llmgoat-cpu -d
sudo systemctl restart llmgoat-log-extractor.service
```

**THM VPN disconnected**
```bash
ssh kali@192.168.56.106
sudo openvpn --config /home/kali/thm.ovpn --daemon --log /tmp/thm-vpn.log
ip addr show tun0
```

**rockyou.txt missing on Kali**
```bash
ssh kali@192.168.56.106 "cp /usr/share/wordlists/rockyou.txt.gz /tmp/ && gunzip /tmp/rockyou.txt.gz"
```
