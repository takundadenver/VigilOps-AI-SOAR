"""
VigilOps CTF State Machine (v5)
Autonomous Capture The Flag solver utilizing Tree of Thoughts planning
and dynamic Model Context Protocol (MCP) tool execution via Kali Linux.
"""

import os
import sys
import re
import json
import time
import asyncio
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
import openai
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession

# --- Configuration ---
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY")

KALI_MCP_URL = "http://192.168.56.106:8005/sse"
CTF_LESSONS_FILE = "./offensive_playbooks/ctf/lessons_learned.txt"
MAX_CYCLES = 50
MAX_DEAD_ENDS = 3
PAUSE_INTERVAL = 5
MAX_MESSAGES = 14
MAX_OUTPUT_IN_MSG = 400
MAX_CONSEC_ERRORS = 3

if not DEEPSEEK_API_KEY:
    print("\n[-] FATAL CONFIG ERROR: DEEPSEEK_API_KEY environment variable not found.")
    sys.exit(1)

client_ai = openai.OpenAI(
    api_key=DEEPSEEK_API_KEY,
    base_url="https://api.deepseek.com"
)

VALID_TOOLS = {
    "nmap_scan", "gobuster_dir", "ffuf_fuzz", "nikto_scan",
    "sqlmap_scan", "curl_request", "hydra_brute", "john_crack",
    "hashcat_crack", "binwalk_analyze", "exiftool_analyze",
    "steghide_extract", "strings_analyze", "enum4linux_scan",
    "smbclient_enum", "run_command", "download_file"
}

TOOL_LIST_HINT = (
    "VALID TOOLS ONLY: nmap_scan, gobuster_dir, ffuf_fuzz, nikto_scan, "
    "sqlmap_scan, curl_request, hydra_brute, john_crack, hashcat_crack, "
    "binwalk_analyze, exiftool_analyze, steghide_extract, strings_analyze, "
    "enum4linux_scan, smbclient_enum, run_command, download_file. "
    "NO ftp/ssh/sshpass tools — use run_command for everything."
)

FLAG_PATTERNS_BY_PLATFORM = {
    "thm": [r"THM\{[^}]+\}"],
    "htb": [r"HTB\{[^}]+\}"],
    "picoctf": [r"picoCTF\{[^}]+\}"],
    "generic": [r"flag\{[^}]+\}", r"FLAG\{[^}]+\}"]
}

UNIVERSAL_FLAG_PATTERNS = [
    r"THM\{[^}]+\}", r"HTB\{[^}]+\}", r"picoCTF\{[^}]+\}",
    r"flag\{[^}]+\}", r"FLAG\{[^}]+\}", r"ctf\{[^}]+\}", r"DUCTF\{[^}]+\}",
    r"user\.txt[:\s\n]+([^\n]{5,60})", r"root\.txt[:\s\n]+([^\n]{5,60})",
]

PLAIN_TEXT_FLAG_SIGNALS = [
    "good job", "well done", "congratulations", "you made it",
    "flag{", "FLAG{", "you got it", "pwned", "rooted"
]


class CTFCategory(Enum):
    WEB = "web";
    CRYPTO = "crypto";
    FORENSICS = "forensics"
    PWN = "pwn";
    REVERSE = "reverse";
    OSINT = "osint"
    NETWORK = "network";
    MISC = "misc";
    UNKNOWN = "unknown"


class State(Enum):
    RECON = "RECON";
    ANALYZE = "ANALYZE";
    EXECUTE = "EXECUTE"
    DEAD_END = "DEAD_END";
    FLAG_FOUND = "FLAG_FOUND";
    REPORT = "REPORT"


@dataclass
class CTFContext:
    target: str
    platform: str
    challenge_name: str
    challenge_desc: str
    flag_format: str
    category: CTFCategory = CTFCategory.UNKNOWN
    state: State = State.RECON
    flags_found: list = field(default_factory=list)
    attack_paths: list = field(default_factory=list)
    current_path: int = 0
    dead_end_count: int = 0
    cycle_count: int = 0
    consec_errors: int = 0
    tool_outputs: list = field(default_factory=list)
    solved: bool = False
    start_time: float = field(default_factory=time.time)
    recon_summary: str = ""
    last_tool: str = ""

    def add_output(self, tool: str, target: str, output: str):
        self.last_tool = tool
        self.tool_outputs.append({
            "cycle": self.cycle_count, "tool": tool,
            "target": target, "output": output[:400]
        })

    def get_history(self) -> str:
        if not self.tool_outputs:
            return "No tools run yet."
        lines = []
        for e in self.tool_outputs[-5:]:
            safe = e['output'][:100].replace('"', "'").replace('\\', '/').replace('\n', ' ').replace('\r', '')
            safe = re.sub(r'[^\x20-\x7E]', '', safe)
            lines.append(f"[C{e['cycle']}] {e['tool']} → {safe}...")
        return "\n".join(lines)


def sanitize_for_json(text: str, max_len: int = MAX_OUTPUT_IN_MSG) -> str:
    text = text[:max_len].replace('\\', '/').replace('"', "'")
    return re.sub(r'[^\x20-\x7E\n]', '', text)


def detect_flags(text: str, platform: str = "generic", custom: str = "", last_tool: str = "") -> list:
    found = []
    patterns = FLAG_PATTERNS_BY_PLATFORM.get(platform.lower(), []) + UNIVERSAL_FLAG_PATTERNS
    if custom:
        patterns.append(custom)
    for p in patterns:
        try:
            for m in re.findall(p, text, re.IGNORECASE | re.MULTILINE):
                if isinstance(m, tuple):
                    m = next((g for g in m if g), "")
                if m and len(m) > 5:
                    found.append(m.strip())
        except re.error:
            pass

    if last_tool == "run_command":
        lines = [l.strip() for l in text.split('\n') if l.strip()]
        for line in lines:
            line_lower = line.lower()
            if any(signal in line_lower for signal in PLAIN_TEXT_FLAG_SIGNALS):
                if 5 < len(line) < 80:
                    found.append(line)
    return list(set(found))


async def _call_kali(tool_name: str, arguments: dict) -> str:
    async with sse_client(KALI_MCP_URL) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, arguments)
            return "\n".join(b.text for b in result.content if hasattr(b, "text"))


def run_kali_tool(tool_name: str, arguments: dict) -> str:
    try:
        return asyncio.run(_call_kali(tool_name, arguments))
    except Exception as e:
        return f"[-] Kali MCP error: {e}"


def load_lessons() -> str:
    if not os.path.exists(CTF_LESSONS_FILE):
        return "No previous CTF lessons."
    with open(CTF_LESSONS_FILE, "r", encoding="utf-8") as f:
        content = f.read()
    return content[-3000:] if len(content) > 3000 else content


def prune(messages: list) -> list:
    if len(messages) > MAX_MESSAGES:
        pruned = messages[:1] + messages[-(MAX_MESSAGES - 1):]
        print(f"[*] Pruned context window: {len(messages)} → {len(pruned)} messages.")
        return pruned
    return messages


def make_anchor(ctx: CTFContext) -> dict:
    path = ctx.attack_paths[ctx.current_path] if ctx.attack_paths else {}
    return {
        "role": "user",
        "content": (
            f"CHALLENGE: {ctx.challenge_name} | TARGET: {ctx.target} | PLATFORM: {ctx.platform.upper()}\n"
            f"RECON: {ctx.recon_summary[:400]}\nFLAGS SO FAR: {ctx.flags_found}\n"
            f"CURRENT PATH {ctx.current_path + 1}: {path.get('name', '')}\n"
        )
    }


def confirm_flag(flag: str, existing_flags: list, auto_mode: bool) -> bool:
    if flag in existing_flags:
        print(f"[*] Duplicate flag skipped: {flag}")
        return False

    print(f"\n[+] POTENTIAL FLAG DETECTED: {flag}")
    is_wrapped = any(flag.upper().startswith(p) for p in ["THM{", "HTB{", "PICOCTF{", "FLAG{", "CTF{"])
    is_plain_flag = any(s in flag.lower() for s in PLAIN_TEXT_FLAG_SIGNALS)

    if auto_mode and (is_wrapped or is_plain_flag):
        print("[*] Auto-confirming flag.")
        return True
    if auto_mode:
        print("[-] Ambiguous format. Operator confirmation needed.")

    return input("[?] Valid flag? (y/n): ").strip().lower() == 'y'


def ask_continue(ctx: CTFContext, auto_mode: bool) -> bool:
    print(f"\n[+] Flag #{len(ctx.flags_found)} confirmed: {ctx.flags_found[-1]}")
    if auto_mode and len(ctx.flags_found) < 2:
        print("[*] Continuing sequence for root flag...")
        return True
    if auto_mode:
        return False
    return input("[?] Continue for root flag? (y/n): ").strip().lower() == 'y'


def state_recon(ctx: CTFContext) -> str:
    print(f"\n[*] STATE: RECON — Scanning {ctx.target}...")
    nmap = run_kali_tool("nmap_scan", {"target": ctx.target, "ports": "top1000", "flags": "-sV -sC -T4"})
    ctx.add_output("nmap", ctx.target, nmap)
    print(f"[+] Nmap scan complete ({len(nmap)} chars)")

    web = ""
    for port in [80, 443, 8080, 8000]:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{ctx.target}" if port in [80, 443] else f"{scheme}://{ctx.target}:{port}"
        r = run_kali_tool("curl_request", {"url": url, "flags": "-L -k -s -m 5"})
        if "Connection refused" not in r and "timed out" not in r.lower():
            web += f"\n--- {url} ---\n{r[:200]}\n"
            print(f"[+] Web service detected: {url}")

    ctx.add_output("curl-probe", ctx.target, web)
    full = nmap + "\n\n" + web
    ctx.recon_summary = sanitize_for_json(full, 800)
    return full


def state_analyze(ctx: CTFContext, recon: str) -> tuple:
    print(f"\n[*] STATE: ANALYZE — Generating attack tree...")
    lessons = load_lessons()

    prompt = f"""CTF solver. Analyze recon, plan 3 attack paths.
CHALLENGE: {ctx.challenge_name} | TARGET: {ctx.target} | PLATFORM: {ctx.platform.upper()}
RECON:\n{sanitize_for_json(recon, 2000)}
LESSONS:\n{lessons[:1200]}

JSON only (no markdown):
{{"category":"web","reasoning":"brief","attack_paths":[
  {{"path_id":1,"name":"SSH mitch:secret to get flags","probability":"high","steps":[]}},
  {{"path_id":2,"name":"CVE-2019-9053 SQLi","probability":"medium","steps":[]}}
]}}"""

    try:
        r = client_ai.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            response_format={"type": "json_object"},
            max_tokens=1000
        )
        data = json.loads(r.choices[0].message.content.strip())
        cat = CTFCategory(data.get("category", "misc").lower())
        paths = data.get("attack_paths", [])

        print(f"[+] Category mapped: {cat.value.upper()}")
        for p in paths:
            print(f"    - Path {p['path_id']}: {p['name']} (Prob: {p.get('probability', '?')})")
        return cat, paths
    except Exception as e:
        print(f"[-] Analysis engine error: {e}")
        return CTFCategory.MISC, [{"path_id": 1, "name": "Direct SSH Fallback", "probability": "high", "steps": []}]


def state_execute(ctx: CTFContext, messages: list) -> tuple:
    messages = prune(messages)
    path = ctx.attack_paths[ctx.current_path] if ctx.attack_paths else {}

    system = f"""HoneyBadger CTF solver.
TARGET: {ctx.target} | PLATFORM: {ctx.platform.upper()} | FLAGS FOUND: {ctx.flags_found}
CURRENT PATH {ctx.current_path + 1}: {path.get('name', '')}

HISTORY:
{ctx.get_history()}

{TOOL_LIST_HINT}

JSON ONLY:
Run: {{"action":"RUN_TOOL","tool":"run_command","args":{{"command":"cmd","timeout":30}},"reasoning":"why"}}
Flag: {{"action":"FLAG_FOUND","flag":"flag{{value}}","reasoning":"found in file"}}
Done: {{"action":"DEAD_END","reasoning":"exhausted"}}"""

    try:
        r = client_ai.chat.completions.create(
            model="deepseek-chat",
            messages=messages + [{"role": "system", "content": system}],
            temperature=0.2,
            response_format={"type": "json_object"},
            max_tokens=300
        )
        parsed = json.loads(r.choices[0].message.content.strip())
        ctx.consec_errors = 0

    except Exception as e:
        ctx.consec_errors += 1
        if ctx.consec_errors >= MAX_CONSEC_ERRORS:
            ctx.consec_errors = 0
            return False, "DEAD_END", "Max JSON errors reached."
        return False, "JSON_ERROR", ""

    action = parsed.get("action", "")
    reasoning = parsed.get("reasoning", "")

    if action == "RUN_TOOL":
        tool = parsed.get("tool", "").strip()
        args = parsed.get("args", {})

        if tool not in VALID_TOOLS:
            ctx.consec_errors += 1
            return False, "TOOL_ERROR", f"Invalid tool '{tool}'. {TOOL_LIST_HINT}"

        print(f"\n[*] Executing Tool: {tool}")
        print(f"    Args: {json.dumps(args)[:120]}")

        output = run_kali_tool(tool, args)
        ctx.add_output(tool, str(args.get("target", args.get("url", args.get("command", "")))), output)
        ctx.consec_errors = 0

        flags = detect_flags(output, ctx.platform, ctx.flag_format, tool)
        if flags:
            return True, flags[0], output

        safe_output = sanitize_for_json(output, MAX_OUTPUT_IN_MSG)
        print(f"[+] Execution complete ({len(output)} chars returned).")
        return False, "", safe_output

    elif action == "FLAG_FOUND":
        return True, parsed.get("flag", ""), ""

    elif action == "DEAD_END":
        print(f"\n[-] DEAD END DECLARED: {reasoning}")
        return False, "DEAD_END", reasoning

    return False, "", str(parsed)


def save_lessons(ctx: CTFContext):
    print("\n[*] Saving CTF episodic memory...")
    elapsed = time.time() - ctx.start_time
    history = "\n".join(f"C{e['cycle']}: {e['tool']} → {e['output'][:100]}" for e in ctx.tool_outputs)

    prompt = f"""CTF debrief. EXACT commands only.
CHALLENGE: {ctx.challenge_name} | RESULT: {"SOLVED" if ctx.flags_found else "UNSOLVED"}
FLAGS: {ctx.flags_found} | TIME: {elapsed:.0f}s | CYCLES: {ctx.cycle_count}
HISTORY:\n{history[:2000]}
Write concise debrief including WINNING TECHNIQUE, FAILED paths, and NEXT TIME FIRST actions."""

    try:
        r = client_ai.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1, max_tokens=600
        )
        lessons = r.choices[0].message.content.strip()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        entry = f"\n\n{'=' * 60}\nCTF DEBRIEF — {timestamp} | {ctx.platform.upper()} | {'SOLVED' if ctx.flags_found else 'UNSOLVED'} | Flags: {len(ctx.flags_found)}\n{'=' * 60}\n{lessons}\n"

        os.makedirs(os.path.dirname(CTF_LESSONS_FILE), exist_ok=True)
        with open(CTF_LESSONS_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
        print(f"[+] Memory successfully written to {CTF_LESSONS_FILE}")
    except Exception as e:
        print(f"[-] Episodic memory extraction failed: {e}")


def launch_ctf_siege(target: str, challenge_name: str, challenge_desc: str, platform: str = "thm",
                     flag_format: str = "", auto_mode: bool = True) -> Optional[str]:
    print("==================================================")
    print("HONEYBADGER AUTONOMOUS CTF SOLVER ONLINE")
    print(f"Target: {target} | Platform: {platform.upper()}")
    print("==================================================")

    if not flag_format:
        flag_format = {"htb": r"HTB\{[^}]+\}", "thm": r"THM\{[^}]+\}", "picoctf": r"picoCTF\{[^}]+\}",
                       "generic": r"flag\{[^}]+\}"}.get(platform.lower(), r"THM\{[^}]+\}")

    ctx = CTFContext(target=target, platform=platform, challenge_name=challenge_name, challenge_desc=challenge_desc,
                     flag_format=flag_format)

    recon_data = state_recon(ctx)
    ctx.state = State.ANALYZE
    ctx.category, ctx.attack_paths = state_analyze(ctx, recon_data)

    if not ctx.attack_paths:
        print("[-] Aborting: No viable attack paths generated.")
        save_lessons(ctx)
        return None

    ctx.state = State.EXECUTE
    messages = [make_anchor(ctx)]

    while ctx.cycle_count < MAX_CYCLES:
        ctx.cycle_count += 1
        print(
            f"\n[*] Cycle {ctx.cycle_count} | Path {ctx.current_path + 1}/{len(ctx.attack_paths)} | Errors: {ctx.consec_errors}")

        flag_found, signal, output = state_execute(ctx, messages)

        if signal == "JSON_ERROR": continue
        if signal == "TOOL_ERROR":
            messages.append({"role": "user", "content": f"Previous failed. {output[:200]} Try again."})
            messages = prune(messages)
            continue

        if flag_found and signal not in ("DEAD_END", "REPORT", "JSON_ERROR", "TOOL_ERROR"):
            if confirm_flag(signal, ctx.flags_found, auto_mode):
                ctx.flags_found.append(signal)
                if ask_continue(ctx, auto_mode):
                    messages.append({"role": "user",
                                     "content": f"Flag {len(ctx.flags_found)} confirmed: {signal}\nNow target root flag."})
                    continue
                else:
                    ctx.solved = True
                    break
            else:
                messages.append({"role": "user", "content": "False positive. Continue search."})

        elif signal == "DEAD_END":
            ctx.dead_end_count += 1
            if ctx.current_path + 1 < len(ctx.attack_paths):
                ctx.current_path += 1
                ctx.state = State.EXECUTE
                print(
                    f"[*] Pivoting to Path {ctx.current_path + 1}: {ctx.attack_paths[ctx.current_path].get('name', '')}")
                messages = [make_anchor(ctx)]
            elif ctx.dead_end_count >= MAX_DEAD_ENDS:
                print("\n[-] All attack paths exhausted.")
                break
            else:
                ctx.current_path = 0
                messages = [make_anchor(ctx)]

        elif signal == "REPORT":
            break

        else:
            messages.append(
                {"role": "assistant", "content": json.dumps({"action": "RUN_TOOL", "summary": output[:100]})})
            messages.append(
                {"role": "user", "content": f"OUTPUT:\n{output[:MAX_OUTPUT_IN_MSG]}\n\nFlags: {ctx.flags_found}"})
            messages = prune(messages)

        if ctx.cycle_count % PAUSE_INTERVAL == 0:
            guidance = input("\n[?] Tactical Guidance (Enter=continue, 'exit'=abort): ").strip()
            if guidance.lower() == "exit":
                print("[*] Engagement aborted by operator.")
                break
            elif guidance:
                ctx.consec_errors = 0
                messages.append({"role": "user", "content": f"OPERATOR DIRECTIVE: {guidance}. Execute immediately."})
                messages = prune(messages)

    ctx.state = State.REPORT
    ctx.solved = len(ctx.flags_found) > 0
    elapsed = time.time() - ctx.start_time

    print("\n==================================================")
    print("CTF SIEGE REPORT")
    print("==================================================")
    print(f"Result:     {'SOLVED' if ctx.solved else 'UNSOLVED'}")
    for i, f in enumerate(ctx.flags_found, 1): print(f"Flag {i}:     {f}")
    print(f"Time:       {elapsed:.0f}s")

    save_lessons(ctx)
    return ctx.flags_found[0] if ctx.flags_found else None