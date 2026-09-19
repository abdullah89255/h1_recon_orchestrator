#!/usr/bin/env python3
"""
h1_recon_orchestrator.py - HackerOne 侦察编排脚本
用法: python h1_recon_orchestrator.py -d example.com -o ./output

注意: 运行前确认目标在 HackerOne scope 内，且程序允许主动扫描。
"""

import argparse
import subprocess
import json
import os
import sys
from pathlib import Path
from datetime import datetime

def run(cmd, output_file=None):
    """执行 shell 命令，可选保存输出。"""
    print(f"[*] Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            print(f"[!] Command failed: {result.stderr[:500]}")
            return None
        if output_file:
            with open(output_file, "w") as f:
                f.write(result.stdout)
            print(f"[+] Saved to {output_file}")
        return result.stdout
    except subprocess.TimeoutExpired:
        print("[!] Command timed out")
        return None
    except FileNotFoundError:
        print(f"[!] Tool not found: {cmd[0]}. Install it first.")
        return None

def check_tools():
    """确认必需工具已安装。"""
    tools = ["subfinder", "httpx", "gobuster", "nuclei"]
    missing = []
    for t in tools:
        if subprocess.run(["which", t], capture_output=True).returncode != 0:
            missing.append(t)
    if missing:
        print(f"[!] Missing tools: {', '.join(missing)}")
        print("    Install via: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        print("                go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        print("                go install github.com/OJ/gobuster/v3@latest")
        print("                go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        sys.exit(1)
    print("[+] All tools present")

def recon_subdomains(domain, outdir):
    """子域名枚举 + 存活探测。"""
    subs_file = outdir / "subdomains.txt"
    live_file = outdir / "live_hosts.txt"
    
    run(["subfinder", "-d", domain, "-silent", "-o", str(subs_file)])
    if subs_file.exists():
        run(["httpx", "-l", str(subs_file), "-silent", "-o", str(live_file), 
             "-title", "-tech-detect", "-status-code"])
    return live_file

def scan_directories(url, outdir, wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"):
    """目录爆破（使用 godirb 或 gobuster）。"""
    if not os.path.exists(wordlist):
        print(f"[!] Wordlist not found: {wordlist}, skipping directory scan")
        return None
    out = outdir / "directories.txt"
    run(["gobuster", "dir", "-u", url, "-w", wordlist, "-o", str(out), 
         "-q", "--no-error", "-t", "20"], output_file=None)
    return out

def run_nuclei(targets_file, outdir):
    """Nuclei 模板扫描（需要确认 scope 允许）。"""
    out = outdir / "nuclei_results.json"
    print("[*] Running nuclei (确认 scope 允许主动扫描)...")
    run(["nuclei", "-l", str(targets_file), "-json", "-o", str(out), 
         "-severity", "low,medium,high,critical", "-silent"], output_file=None)
    return out

def main():
    parser = argparse.ArgumentParser(description="HackerOne 侦察编排")
    parser.add_argument("-d", "--domain", required=True, help="目标域名 (在 scope 内)")
    parser.add_argument("-o", "--output", default="./h1_output", help="输出目录")
    parser.add_argument("--skip-nuclei", action="store_true", 
                        help="跳过 Nuclei（当 scope 不允许主动扫描时）")
    args = parser.parse_args()

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    print(f"""
========================================
HackerOne Recon Orchestrator
Target: {args.domain}
Output: {outdir.resolve()}
========================================
[!] 确认事项:
    1. 目标在 H1 scope 内
    2. 程序允许主动扫描/自动化
    3. 遵守速率限制
========================================
""")

    check_tools()

    # Phase 1: 子域名 + 存活
    live_file = recon_subdomains(args.domain, outdir)

    # Phase 2: 目录爆破（对主域名）
    scan_directories(f"https://{args.domain}", outdir)

    # Phase 3: Nuclei（可选）
    if not args.skip_nuclei and live_file and live_file.exists():
        run_nuclei(live_file, outdir)
    else:
        print("[*] Skipping nuclei")

    print(f"\n[+] Recon complete. Check {outdir.resolve()}")
    print("[*] 下一步: 手动审查发现，验证每个候选漏洞")

if __name__ == "__main__":
    main()
