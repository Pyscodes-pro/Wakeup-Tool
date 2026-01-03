import time
import requests
import json
import sys
import socket
import ssl
import random
import re
import os
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.live import Live
from rich.align import Align

console = Console()
GLOBAL_WIDTH = 98
WATERMARK = "WAKEUP TOOL REPORT BY MELVIN-LAB"

# ================= DATABASE SISTEM & BAHASA =================
session_data = {
    "user_name": "GUEST",
    "target": "NOT_SET",
    "lang": "EN",
    "status": "READY",
    "scans": {}
}

STRINGS = {
    "EN": {
        "welcome": "Hello, I'M Melvin Assistant",
        "ask_name": "Please enter your name to access the system: ",
        "m1": "INITIALIZE TARGET", "m2": "COMMAND CENTER", "m3": "REPORT CENTER",
        "m4": "SYSTEM GUIDE", "m5": "SWITCH LANGUAGE", "m6": "TERMINATE SYSTEM",
        "c1": "SSL Intelligence", "c2": "WHOIS Deep Detail",
        "c3": "Directory Scan", "c4": "CMS Tech Profiler",
        "c5": "Fast Port Scan", "c6": "Security Header Audit",
        "c7": "Subdomain Recon", "c8": "Security Files Probe",
        "c9": "DNS Deep Lookup", "c10": "Reverse IP Lookup",
        "c11": "WAF Detection", "c12": "Email/Social Scraper",
        "c13": "Geo-IP Tracker", "c14": "Ping Latency Test",
        "c15": "Origin IP Finder (WAF Bypass)",
        "c0": "RETURN TO BASE",
        "prompt": "MELVIN@NEURAL >>> ", "select": "SELECT MODULE ID >>> ",
        "wait": "PRESS ENTER TO CONTINUE...", "set_target": "ENTER DOMAIN (example.com): ",
        "lock": "TARGET LOCK ACQUIRED",
        "donate_title": "🚀 SUPPORT THE PROJECT",
        "donate_msg": "Fuel the innovation! Your support helps me maintain and provide regular updates. Every contribution matters.",
        "loading": "Processing Neural Request...",
        "syncing": "Syncing Language Packs...",
        "rep_title": "NEURAL REPORT CENTER",
        "rep_save_txt": "SAVE AS .TXT REPORT",
        "rep_save_json": "SAVE AS .JSON DATA",
        "rep_msg": "Select report format to export your scan data.",
        "goodbye": "GOOD BYE, OPERATOR. NEURAL LINK TERMINATED."
    },
    "ID": {
        "welcome": "Halo, SAYA Melvin Assistant",
        "ask_name": "Silakan masukkan nama Anda untuk akses sistem: ",
        "m1": "ATUR TARGET", "m2": "PUSAT KOMANDO", "m3": "PUSAT LAPORAN",
        "m4": "PANDUAN SISTEM", "m5": "GANTI BAHASA", "m6": "KELUAR SISTEM",
        "c1": "Intelijen SSL", "c2": "Detail WHOIS",
        "c3": "Scan Direktori", "c4": "Profil Teknologi CMS",
        "c5": "Scan Port Cepat", "c6": "Audit Header Keamanan",
        "c7": "Pencarian Subdomain", "c8": "Cek File Keamanan",
        "c9": "Cek DNS Mendalam", "c10": "Reverse IP Lookup",
        "c11": "Deteksi Firewall", "c12": "Email/Sosial Scraper",
        "c13": "Pelacak Geo-IP", "c14": "Tes Ping & Latensi",
        "c15": "Cari IP Server Asli (Bypass WAF)",
        "c0": "KEMBALI KE MENU",
        "prompt": "MELVIN@NEURAL >>> ", "select": "PILIH ID MODUL >>> ",
        "wait": "TEKAN ENTER UNTUK LANJUT...", "set_target": "MASUKKAN DOMAIN (contoh.com): ",
        "lock": "TARGET BERHASIL DIKUNCI",
        "donate_title": "🚀 DUKUNG PENGEMBANGAN",
        "donate_msg": "Dukung inovasi ini! Kontribusi Anda membantu saya memberikan update modul secara rutin. Setiap dukungan sangat berarti.",
        "goodbye": "SAMPAI JUMPA, OPERATOR. KONEKSI NEURAL DIPUTUS.",
        "loading": "Memproses Permintaan Neural...",
        "syncing": "Menyinkronkan Paket Bahasa...",
        "rep_title": "PUSAT LAPORAN NEURAL",
        "rep_save_txt": "SIMPAN SEBAGAI LAPORAN .TXT",
        "rep_save_json": "SIMPAN SEBAGAI DATA .JSON",
        "rep_msg": "Pilih format laporan untuk mengekspor data hasil scan."
    }
}

ASCII_MELVIN = """[bold cyan]
█▀▄▀█ █▀▀ █░░ █░█ █ █▄░█ ▄▄ █░░ ▄▀█ █▄▄
█░▀░█ ██▄ █▄▄ ▀▄▀ █ █░▀█ ░░ █▄▄ █▀█ █▄█   [white]v25.6[/][/bold cyan]"""

RAW_LOGO = """[bold blue]
 _       _____    __ __ ________  ______     ___    _   ______  _______
| |     / /   |  / //_// ____/ / / / __ \   /   |  / | / / /\ \/ /__  /
| | /| / / /| | / ,<  / __/ / / / / /_/ /  / /| | /  |/ / /  \  /  / / 
| |/ |/ / ___ |/ /| |/ /___/ /_/ / ____/  / ___ |/ /|  / /___/ /  / /__
|__/|__/_/  |_/_/ |_/_____/\____/_/      /_/  |_/_/ |_/_____/_/  /____/
                             |_| [bold white]NEURAL-OVERLORD[/][/bold blue]"""

# ================= UTILITY: CLEANERS =================

def filter_junk(text):
    if not text: return ""
    text = text.replace('\x1b[200~', '').replace('\x1b[201~', '')
    text = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)
    text = "".join(c for c in text if c.isprintable())
    return text.strip()

def sanitize_domain(raw_input):
    text = filter_junk(raw_input).lower()
    try:
        text = re.sub(r'^[a-z0-9]+://', '', text)
        text = re.sub(r'^www\.', '', text)
        text = text.split('/')[0].split('?')[0].split('#')[0]
        text = re.sub(r'[^a-z0-9\.\-]', '', text)
        return text if text else "NOT_SET"
    except: return "NOT_SET"

# ================= UI & ANIMATIONS =================

def neural_boot():
    console.clear(); console.print(Align.center(ASCII_MELVIN))
    steps = ["Initalizing Neural Link", "Loading Core Modules", "Syncing Database", "System Overlord Online"]
    with Progress(SpinnerColumn("dots"), TextColumn("[bold blue]{task.description}"), BarColumn(bar_width=40)) as progress:
        task = progress.add_task("Booting...", total=len(steps))
        for step in steps:
            time.sleep(0.3)
            progress.update(task, advance=1, description=f"[cyan]{step}")

def get_header():
    L = session_data["lang"]; now = datetime.now().strftime("%H:%M:%S")
    target = session_data["target"]; user = session_data["user_name"]
    status_text = f"[blink bold green]● ONLINE[/]" if session_data["status"] == "READY" else f"[blink bold yellow]● BUSY[/]"
    header_grid = Table.grid(expand=True)
    header_grid.add_column(justify="left", ratio=1); header_grid.add_column(justify="center", ratio=1); header_grid.add_column(justify="right", ratio=1)
    header_grid.add_row(f"[bold magenta]👤 {user}[/] | {status_text}", f"[bold white]🎯 TARGET:[/] [bold cyan]{target}[/]", f"[bold blue]🕒 {now}[/] | [bold white]{L}[/]")
    return Panel(header_grid, width=GLOBAL_WIDTH, border_style="bright_blue", title="[bold white]WAKEUP COMMAND INTERFACE[/]", title_align="left")

def action_loading(message, duration=1.0):
    with console.status(f"[bold yellow]{message}", spinner="dots"):
        time.sleep(duration)

def log_scan(module_name, result):
    session_data["scans"][module_name] = result

# ================= 15 SUPREME MODULES =================

def run_ssl(domain):
    with console.status("[bold cyan]Analyzing SSL...", spinner="dots"):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    res = f"Cipher: {ssock.version()} | Handshake: OK"
                    log_scan("SSL Intelligence", res); console.print(Panel(res, title="SSL INFO", border_style="cyan", width=GLOBAL_WIDTH))
        except: log_scan("SSL Intelligence", "Failed"); console.print("[red][!] SSL Error.")

def run_whois(domain):
    with console.status("[bold green]Fetching WHOIS...", spinner="dots"):
        try:
            r = requests.get(f"https://rdap.org/domain/{domain}", timeout=10).json()
            res = f"Domain: {r.get('handle')} | Status: {', '.join(r.get('status', []))}"
            log_scan("WHOIS Deep Detail", res); console.print(Panel(res, title="WHOIS DATA", width=GLOBAL_WIDTH))
        except: console.print("[red][!] WHOIS Error.")

def run_dir_scan(domain):
    paths = ["/admin", "/.env", "/backup", "/config", "/wp-login.php"]
    found = []
    with Progress(SpinnerColumn("dots"), BarColumn(), TextColumn("[yellow]{task.description}")) as prog:
        task = prog.add_task("Fuzzing...", total=len(paths))
        for p in paths:
            try:
                r = requests.get(f"http://{domain}{p}", timeout=3, allow_redirects=False)
                if r.status_code == 200: found.append(p)
            except: pass
            prog.advance(task)
    res = f"Found: {', '.join(found) if found else 'None'}"
    log_scan("Directory Scan", res); console.print(Panel(res, title="DIR SCAN", width=GLOBAL_WIDTH))

def run_cms(domain):
    with console.status("[bold green]Profiling Stack...", spinner="dots"):
        try:
            r = requests.get(f"http://{domain}", timeout=10)
            tech = "WordPress" if "wp-content" in r.text else "Generic"
            res = f"CMS: {tech} | Server: {r.headers.get('Server', 'N/A')}"
            log_scan("CMS Tech Profiler", res); console.print(Panel(res, title="CMS TECH", width=GLOBAL_WIDTH))
        except: console.print("[red]CMS Error.")

def run_port_scan(domain):
    ports = [21, 22, 80, 443, 3306]
    open_p = []
    with Progress(SpinnerColumn("dots"), BarColumn(), TextColumn("[bold yellow]{task.description}")) as prog:
        task = prog.add_task("Probing Ports...", total=len(ports))
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.5)
            if s.connect_ex((domain, p)) == 0: open_p.append(str(p))
            s.close(); prog.advance(task)
    res = f"Open Ports: {', '.join(open_p) if open_p else 'None'}"
    log_scan("Fast Port Scan", res); console.print(Panel(res, title="PORTS", width=GLOBAL_WIDTH))

def run_header(domain):
    with console.status("[bold yellow]Auditing Headers...", spinner="dots"):
        try:
            r = requests.get(f"https://{domain}", timeout=10)
            missing = [x for x in ["Content-Security-Policy", "X-Frame-Options"] if x not in r.headers]
            res = f"Missing: {', '.join(missing) if missing else 'Secure'}"
            log_scan("Security Header Audit", res); console.print(Panel(res, title="HEADERS", width=GLOBAL_WIDTH))
        except: console.print("[red]Header Error.")

def run_subdomain(domain):
    with console.status("[bold magenta]Discovery Subdomains...", spinner="dots"):
        try:
            r = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=10).json()
            subs = list(set([i['name_value'] for i in r[:5]]))
            res = f"Subdomains: {', '.join(subs)}"
            log_scan("Subdomain Recon", res); console.print(Panel(res, title="SUBDOMAINS", width=GLOBAL_WIDTH))
        except: console.print("[red]Subdomain Error.")

def run_sec_files(domain):
    files = ["/robots.txt", "/.env", "/security.txt"]
    found = []
    with Progress(SpinnerColumn("dots"), BarColumn(), TextColumn("[bold cyan]{task.description}")) as prog:
        task = prog.add_task("Probing Files...", total=len(files))
        for f in files:
            try:
                r = requests.get(f"http://{domain}{f}", timeout=3)
                if r.status_code == 200: found.append(f)
            except: pass
            prog.advance(task)
    res = f"Sensitive Files: {', '.join(found) if found else 'None'}"
    log_scan("Security Files Probe", res); console.print(Panel(res, title="FILES", width=GLOBAL_WIDTH))

def run_dns(domain):
    with console.status("[bold blue]Querying DNS...", spinner="dots"):
        try:
            ip = socket.gethostbyname(domain)
            res = f"A Record: {ip}"
            log_scan("DNS Deep Lookup", res); console.print(Panel(res, title="DNS", width=GLOBAL_WIDTH))
        except: console.print("[red]DNS Error.")

def run_reverse(domain):
    with console.status("[bold yellow]Reverse IP Lookup...", spinner="dots"):
        try:
            ip = socket.gethostbyname(domain)
            r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=10)
            res = f"Neighbors: {r.text[:100]}..."
            log_scan("Reverse IP Lookup", res); console.print(Panel(res, title="REVERSE IP", width=GLOBAL_WIDTH))
        except: console.print("[red]API Error.")

def run_waf(domain):
    with console.status("[bold red]Detecting WAF...", spinner="dots"):
        try:
            r = requests.get(f"http://{domain}", timeout=5)
            h = r.headers
            waf = "Cloudflare" if "cf-ray" in h else "Sucuri" if "x-sucuri-id" in h else "None"
            res = f"WAF: {waf} | Server: {h.get('Server', 'N/A')}"
            log_scan("WAF Detection", res); console.print(Panel(res, title="WAF SCAN", width=GLOBAL_WIDTH))
        except: console.print("[red]WAF Error.")

def run_scraper(domain):
    with console.status("[bold cyan]Metadata Scraping...", spinner="dots"):
        try:
            r = requests.get(f"http://{domain}", timeout=5)
            emails = re.findall(r'[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}', r.text)
            res = f"Emails Found: {', '.join(list(set(emails))[:2])}"
            log_scan("Email/Social Scraper", res); console.print(Panel(res, title="SCRAPER", width=GLOBAL_WIDTH))
        except: console.print("[red]Scraper Error.")

def run_geoip(domain):
    with console.status("[bold magenta]Geo-Mapping...", spinner="dots"):
        try:
            ip = socket.gethostbyname(domain)
            geo = requests.get(f"http://ip-api.com/json/{ip}").json()
            res = f"Country: {geo.get('country')} | ISP: {geo.get('isp')}"
            log_scan("Geo-IP Tracker", res); console.print(Panel(res, title="GEO-IP", width=GLOBAL_WIDTH))
        except: console.print("[red]Geo-IP Error.")

def run_ping(domain):
    start = time.time()
    try:
        socket.create_connection((domain, 80), timeout=2)
        lat = round((time.time() - start) * 1000, 2)
        res = f"Latency: {lat}ms"
    except: res = "Latency: Timeout"
    log_scan("Ping Latency Test", res); console.print(Panel(res, title="PING", width=GLOBAL_WIDTH))

def run_origin(domain):
    ips = []
    with Progress(SpinnerColumn("dots"), BarColumn(), TextColumn("[bold red]{task.description}")) as prog:
        task1 = prog.add_task("DNS History...", total=1)
        try:
            r = requests.get(f"https://api.hackertarget.com/dnshistory/?q={domain}", timeout=5)
            ips.extend(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', r.text))
        except: pass
        prog.advance(task1)
        
        task2 = prog.add_task("Subdomain Probing...", total=5)
        for s in ["mail.", "direct.", "dev.", "ftp.", "backend."]:
            try: ips.append(socket.gethostbyname(s+domain))
            except: pass
            prog.advance(task2)
            
    unique = list(set(ips))
    res = f"Origin IPs Found: {', '.join(unique[:5]) if unique else 'Clean/Protected'}"
    log_scan("Origin IP Finder", res); console.print(Panel(res, title="BYPASS SCAN", border_style="red", width=GLOBAL_WIDTH))

# ================= REPORT CENTER (WITH WATERMARK) =================

def save_report_final(fmt):
    L = session_data["lang"]; target = session_data["target"]
    if target == "NOT_SET": return
    
    action_loading(STRINGS[L]["loading"])
    ts = datetime.now().strftime("%H%M")
    name = f"report_{target.replace('.','_')}_{ts}.{fmt.lower()}"
    
    try:
        with open(name, "w") as f:
            if fmt == "JSON":
                session_data["watermark"] = WATERMARK
                json.dump(session_data, f, indent=4)
            else:
                f.write(f"{'='*60}\n  {WATERMARK}\n{'='*60}\n\n")
                f.write(f"REPORT FOR  : {target.upper()}\nOPERATOR    : {session_data['user_name']}\n")
                f.write(f"DATE        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'-'*60}\n\n")
                for m, r in session_data["scans"].items(): f.write(f"[{m}]\n  > {r}\n\n")
                f.write(f"{'-'*60}\n  END OF REPORT - MELVIN LAB\n")
        
        console.print(Panel(f"Saved: [bold cyan]{name}[/]", border_style="green", width=GLOBAL_WIDTH))
    except Exception as e: console.print(f"[red]Error: {e}")

def report_menu():
    L = session_data["lang"]
    while True:
        console.clear(); console.print(get_header())
        rt = Table(width=GLOBAL_WIDTH, border_style="yellow", box=None)
        rt.add_column(width=45); rt.add_column(width=45)
        rt.add_row(f"[1] {STRINGS[L]['rep_save_txt']}", f"[2] {STRINGS[L]['rep_save_json']}")
        rt.add_row("", f"[bold red][0] {STRINGS[L]['c0']}[/]")
        console.print(Panel(Align.center(STRINGS[L]["rep_msg"]), title=STRINGS[L]["rep_title"], border_style="yellow"))
        console.print(Panel(rt, border_style="yellow"))
        c = filter_junk(console.input(f"[bold yellow]{STRINGS[L]['select']}"))
        if c == "0": break
        elif c == "1": save_report_final("TXT")
        elif c == "2": save_report_final("JSON")
        console.input(f"\n{STRINGS[L]['wait']}")

# ================= CORE LOGIC =================

def modular_center():
    L = session_data["lang"]
    while True:
        console.clear(); console.print(get_header())
        m = Table(width=GLOBAL_WIDTH, border_style="magenta", box=None)
        m.add_column(width=45); m.add_column(width=45)
        m_rows = [
            (f"[1] {STRINGS[L]['c1']}", f"[9] {STRINGS[L]['c9']}"),
            (f"[2] {STRINGS[L]['c2']}", f"[10] {STRINGS[L]['c10']}"),
            (f"[3] {STRINGS[L]['c3']}", f"[11] {STRINGS[L]['c11']}"),
            (f"[4] {STRINGS[L]['c4']}", f"[12] {STRINGS[L]['c12']}"),
            (f"[5] {STRINGS[L]['c5']}", f"[13] {STRINGS[L]['c13']}"),
            (f"[6] {STRINGS[L]['c6']}", f"[14] {STRINGS[L]['c14']}"),
            (f"[7] {STRINGS[L]['c7']}", f"[15] {STRINGS[L]['c15']}"),
            (f"[8] {STRINGS[L]['c8']}", f"[bold red][0] {STRINGS[L]['c0']}[/]")
        ]
        for r1, r2 in m_rows: m.add_row(r1, r2)
        console.print(Panel(m, title="COMMAND CENTER", border_style="magenta"))
        c = filter_junk(console.input(f"[bold yellow]{STRINGS[L]['select']}"))
        t = session_data["target"]
        if c == "0": break
        if t == "NOT_SET": console.print("[red]Set target first!"); time.sleep(1); continue
        
        session_data["status"] = "BUSY"
        if c=="1": run_ssl(t)
        elif c=="2": run_whois(t)
        elif c=="3": run_dir_scan(t)
        elif c=="4": run_cms(t)
        elif c=="5": run_port_scan(t)
        elif c=="6": run_header(t)
        elif c=="7": run_subdomain(t)
        elif c=="8": run_sec_files(t)
        elif c=="9": run_dns(t)
        elif c=="10": run_reverse(t)
        elif c=="11": run_waf(t)
        elif c=="12": run_scraper(t)
        elif c=="13": run_geoip(t)
        elif c=="14": run_ping(t)
        elif c=="15": run_origin(t)
        
        session_data["status"] = "READY"
        console.input(f"\n{STRINGS[L]['wait']}")

def main_menu():
    while True:
        L = session_data["lang"]; console.clear()
        console.print(get_header()); console.print(Align.center(RAW_LOGO))
        g = Table.grid(padding=(0, 6)); g.add_column(); g.add_column()
        g.add_row(f"[bold cyan]1.[/] {STRINGS[L]['m1']}", f"[bold cyan]4.[/] {STRINGS[L]['m4']}")
        g.add_row(f"[bold cyan]2.[/] {STRINGS[L]['m2']}", f"[bold cyan]5.[/] {STRINGS[L]['m5']}")
        g.add_row(f"[bold cyan]3.[/] {STRINGS[L]['m3']}", f"[bold red]6.[/] {STRINGS[L]['m6']}")
        console.print(Panel(g, width=GLOBAL_WIDTH, border_style="bright_blue", title="CORE INTERFACE", padding=(1, 10)))
        
        c = filter_junk(console.input(f"[bold cyan]{STRINGS[L]['prompt']}"))
        if c == "1":
            raw = console.input(f"[bold white]{STRINGS[L]['set_target']}")
            cleaned = sanitize_domain(raw)
            if cleaned != "NOT_SET":
                action_loading("Analyzing Neural Trace...", 1.2)
                session_data["target"] = cleaned
                session_data["scans"] = {} # Clear for new target
                console.print(Panel(Align.center(f"[bold green]>>> {STRINGS[L]['lock']} <<<[/]"), width=50, border_style="green"))
                time.sleep(1)
        elif c == "2": modular_center()
        elif c == "3": report_menu()
        elif c == "4":
            action_loading(STRINGS[L]["loading"])
            console.print(Panel("Melvin Assistant v25.6\nAuthor: @melvinpro_05\nSupport: saweria.co/MelvinPro", title="INFO", width=GLOBAL_WIDTH, border_style="green"))
            console.input(f"\n{STRINGS[L]['wait']}")
        elif c == "5":
            session_data["lang"] = "ID" if session_data["lang"]=="EN" else "EN"
            action_loading(STRINGS[session_data["lang"]]["syncing"])
        elif c == "6":
            console.clear(); console.print(Align.center(ASCII_MELVIN))
            console.print(f"\n[bold red]{STRINGS[session_data['lang']]['goodbye']}[/]"); time.sleep(2); sys.exit()

if __name__ == "__main__":
    try:
        neural_boot()
        console.clear(); console.print(Align.center(ASCII_MELVIN))
        L = session_data["lang"]
        donate = Panel(Align.center(f"[white]{STRINGS[L]['donate_msg']}[/]\n\n[bold yellow]Saweria:[/] [bold cyan]https://saweria.co/MelvinPro[/]"), width=75, border_style="gold1", title="DONATION")
        console.print(Align.center(donate))
        name_p = Panel(Align.center(f"[bold white]{STRINGS[L]['ask_name']}[/]"), width=60, border_style="cyan")
        console.print(Align.center(name_p))
        raw_name = console.input(f"\n[bold cyan]  USER@INPUT >>> [/]")
        session_data["user_name"] = filter_junk(raw_name) if raw_name else "Operator"
        main_menu()
    except KeyboardInterrupt: sys.exit()
