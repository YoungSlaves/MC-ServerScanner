#!/usr/bin/env python3
"""
Minecraft Server Scanner – IVON style (fixed)
Scans IP ranges, sorts by version and player count.
"""

import argparse
import ipaddress
import os
import sys
import threading
import time
import queue
import random
import re
import ctypes
from datetime import datetime
from typing import List, Optional, Tuple, Callable

# ==================== ENABLE ANSI ON WINDOWS ====================
def enable_windows_ansi():
    if os.name == 'nt':
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
enable_windows_ansi()

# ==================== THIRD-PARTY IMPORTS ====================
try:
    from mcstatus import JavaServer, BedrockServer
except ImportError:
    print("Please install mcstatus: pip install mcstatus")
    sys.exit(1)

try:
    import socks
except ImportError:
    socks = None

# ==================== COLOUR CLASSES ====================
class Color:
    @staticmethod
    def hex_to_ansi(hex_code: str, is_background: bool = False) -> str:
        hex_code = hex_code.lstrip('#')
        if len(hex_code) == 3:
            hex_code = ''.join(c*2 for c in hex_code)
        r, g, b = int(hex_code[0:2], 16), int(hex_code[2:4], 16), int(hex_code[4:6], 16)
        base = 48 if is_background else 38
        return f"\033[{base};2;{r};{g};{b}m"

    @staticmethod
    def rgb_to_ansi(r: int, g: int, b: int, is_background: bool = False) -> str:
        base = 48 if is_background else 38
        return f"\033[{base};2;{r};{g};{b}m"

class IvonColor:
    RESET = "\033[0m"
    IVON = Color.hex_to_ansi("#cc00aa")          # signature purple
    RED = Color.hex_to_ansi("#ff001e")
    GREEN = Color.hex_to_ansi("#44ff00")
    LIGHTBLACK = Color.hex_to_ansi("#5c5e5b")
    LIGHTBLUE = Color.hex_to_ansi("#03f8fc")
    YELLOW = Color.hex_to_ansi("#fcf803")
    PURPLE = Color.hex_to_ansi("#7903ff")

# ==================== GRADIENT PRINTER ====================
class GradientPrinter:
    @staticmethod
    def gradient(start: Tuple[int, int, int], end: Tuple[int, int, int], steps: int) -> List[Tuple[int, int, int]]:
        if steps < 1:
            return []
        rs = [start[0]]
        gs = [start[1]]
        bs = [start[2]]
        for step in range(1, steps):
            rs.append(round(start[0] + (end[0] - start[0]) * step / steps))
            gs.append(round(start[1] + (end[1] - start[1]) * step / steps))
            bs.append(round(start[2] + (end[2] - start[2]) * step / steps))
        return list(zip(rs, gs, bs))

    @staticmethod
    def validate_hex_color(color: str) -> Tuple[int, int, int]:
        try:
            return Color.hex_to_rgb(color)
        except Exception as e:
            raise ValueError(f"Invalid color format '{color}': {e}") from e

    @classmethod
    def gradient_print(cls, input_text: str, start_color: str, end_color: str, end: str = "\n"):
        def hex_to_rgb(h):
            h = h.lstrip('#')
            if len(h) == 3:
                h = ''.join(c*2 for c in h)
            return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
        start_rgb = hex_to_rgb(start_color)
        end_rgb = hex_to_rgb(end_color)
        steps = max(len(input_text), 1)
        grad = cls.gradient(start_rgb, end_rgb, steps)
        for i, char in enumerate(input_text):
            sys.stdout.write(Color.rgb_to_ansi(*grad[i]) + char)
        sys.stdout.write(IvonColor.RESET + end)
        sys.stdout.flush()

# ==================== TITLE BAR UPDATER ====================
class TitleBarUpdater:
    def __init__(self, stats_provider: Callable[[], str], interval: float = 0.5):
        self.stats_provider = stats_provider
        self.interval = interval
        self._thread = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                title = self.stats_provider()
                if title:
                    self._set_title(title)
            except Exception:
                pass
            time.sleep(self.interval)

    @staticmethod
    def _set_title(title: str) -> None:
        if os.name == "nt":
            # Quote the title to avoid pipe interpretation
            os.system(f"title \"{title}\"")
        else:
            sys.stdout.write(f"\33]0;{title}\a")
            sys.stdout.flush()

# ==================== PROXY PROVIDER ====================
class ProxyProvider:
    def __init__(self, file: str):
        self.file = file
        self.lock = threading.Lock()

    def get(self) -> Optional[str]:
        with self.lock:
            try:
                with open(self.file, "r+", encoding="utf-8") as f:
                    proxies = [p.strip() for p in f if p.strip()]
                    if not proxies:
                        return None
                    proxy = proxies.pop(0)
                    f.seek(0)
                    f.truncate()
                    f.write("\n".join(proxies))
                    return proxy
            except FileNotFoundError:
                return None

# ==================== LOGGER ====================
class IvonLogger:
    def __init__(self):
        self.prefix = f"{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] "

    def log(self, msg: str) -> None:
        print(self.prefix + IvonColor.LIGHTBLACK + msg)

# ==================== CONFIGURATION ====================
DEFAULT_RANGES = [
    "103.15.236.0/23", "202.36.95.0/24",  # Shockbyte
    "104.238.128.0/20", "107.182.224.0/20", "198.12.64.0/19",  # Apex
    "185.249.224.0/22", "194.35.116.0/22", "217.79.176.0/20",  # Bisect
    "138.201.0.0/16", "144.76.0.0/16", "178.63.0.0/16",        # G-PORTAL
    "162.33.0.0/16", "209.58.0.0/17",                          # Nodecraft
    "45.35.0.0/17", "69.174.0.0/16",                           # Akliz
    "185.223.28.0/22", "185.254.192.0/22",                     # PebbleHost
    "51.89.0.0/16", "151.80.0.0/16",                           # Sparked
    "51.75.0.0/16", "54.36.0.0/15",                            # ScalaCube
    "199.15.160.0/20", "199.59.160.0/20",                      # Host Havoc
    "167.114.0.0/16", "192.99.0.0/16", "51.254.0.0/16", "54.37.0.0/16",  # OVH
]

DEFAULT_PORTS = [25565, 25566, 25567, 25570, 25571, 25575, 25580, 25600,
                 25644, 25645, 25646, 25647, 25648, 25649, 19132]

BASE_OUTPUT_DIR = "hits"
STATUS_INTERVAL = 0.3

# Global counters & locks
counter_lock = threading.Lock()
total_scanned = 0
total_found = 0
total_dead = 0
total_errors = 0
print_lock = threading.Lock()
status_stop = threading.Event()
proxy_queue = None
logger = IvonLogger()

# ==================== HELPER FUNCTIONS ====================
def ensure_output_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def create_output_directories():
    now = datetime.now()
    year = now.strftime("%Y")
    month_day = now.strftime("%m-%d")
    hour_min = now.strftime("%H-%M")  # no seconds
    run_dir = os.path.join(BASE_OUTPUT_DIR, year, month_day, hour_min)
    version_dir = os.path.join(run_dir, "versions")
    players_dir = os.path.join(run_dir, "players")
    ensure_output_dir(version_dir)
    ensure_output_dir(players_dir)
    return run_dir, version_dir, players_dir

def create_proxied_socket(proxy_url):
    if socks is None:
        return None
    if proxy_url.startswith('socks5://'):
        parts = proxy_url[8:].split(':')
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 1080
        proxy_type = socks.SOCKS5
    elif proxy_url.startswith('socks4://'):
        parts = proxy_url[8:].split(':')
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 1080
        proxy_type = socks.SOCKS4
    elif proxy_url.startswith('http://'):
        parts = proxy_url[7:].split(':')
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 8080
        proxy_type = socks.HTTP
    else:
        return None
    s = socks.socksocket()
    s.set_proxy(proxy_type, host, port)
    return s

def check_java_server(ip, port, timeout, retries, use_proxy=False):
    for attempt in range(retries):
        try:
            if use_proxy and proxy_queue is not None:
                proxy_url = proxy_queue.get() if proxy_queue else None
                if proxy_url:
                    sock = create_proxied_socket(proxy_url)
                    server = JavaServer(ip, port, timeout=timeout)
                    server._socket = sock
                    status = server.status()
                else:
                    server = JavaServer.lookup(f"{ip}:{port}", timeout=timeout)
                    status = server.status()
            else:
                server = JavaServer.lookup(f"{ip}:{port}", timeout=timeout)
                status = server.status()
            return status
        except Exception:
            if attempt == retries - 1:
                return None
            time.sleep(0.5)
    return None

def check_bedrock_server(ip, port, timeout, retries, use_proxy=False):
    for attempt in range(retries):
        try:
            if use_proxy and proxy_queue is not None:
                proxy_url = proxy_queue.get() if proxy_queue else None
                if proxy_url:
                    sock = create_proxied_socket(proxy_url)
                    server = BedrockServer(ip, port, timeout=timeout)
                    server._socket = sock
                    status = server.status()
                else:
                    server = BedrockServer.lookup(f"{ip}:{port}", timeout=timeout)
                    status = server.status()
            else:
                server = BedrockServer.lookup(f"{ip}:{port}", timeout=timeout)
                status = server.status()
            return status
        except Exception:
            if attempt == retries - 1:
                return None
            time.sleep(0.5)
    return None

def parse_version_string(version_str):
    version_str = str(version_str).strip()
    if not version_str or version_str == "null":
        return "UNKNOWN_VERSION"

    # Proxy ranges
    proxy_patterns = [
        (r'velocity.*?([\d\.]+)-([\d\.]+)', 'Velocity_{}-{}'),
        (r'bungeecord.*?([\d\.]+)-([\d\.]+)', 'BungeeCord_{}-{}'),
        (r'waterfall.*?([\d\.]+)-([\d\.]+)', 'Waterfall_{}-{}'),
        (r'gate.*?([\d\.]+)-([\d\.]+)', 'Gate_{}-{}'),
    ]
    for pattern, fmt in proxy_patterns:
        m = re.search(pattern, version_str, re.I)
        if m:
            return fmt.format(m.group(1), m.group(2))

    # Software names
    software_map = {
        'paper': 'Paper',
        'spigot': 'Spigot',
        'craftbukkit': 'CraftBukkit',
        'bukkit': 'Bukkit',
        'forge': 'Forge',
        'neoforge': 'NeoForge',
        'fabric': 'Fabric',
        'vanilla': 'Vanilla',
        'purpur': 'PurPur',
        'pufferfish': 'Pufferfish',
        'tuinity': 'Tuinity',
        'airplane': 'Airplane',
        'yatopia': 'Yatopia',
        'mohist': 'Mohist',
        'magma': 'Magma',
        'catserver': 'CatServer',
        'arclight': 'Arclight',
    }
    vl = version_str.lower()
    detected = None
    for key, folder in software_map.items():
        if key in vl:
            detected = folder
            break

    ver_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version_str)
    ver_num = ver_match.group(1) if ver_match else None

    if detected and ver_num:
        return f"{detected}_{ver_num}"
    elif detected:
        return detected
    elif ver_num:
        return ver_num
    else:
        return re.sub(r'[^\w\-\.]', '_', version_str)[:50] or "UNKNOWN_VERSION"

def get_player_folder(player_count):
    if player_count == 0:
        return "0"
    elif player_count <= 5:
        return "1-5"
    elif player_count <= 10:
        return "6-10"
    elif player_count <= 20:
        return "11-20"
    elif player_count <= 50:
        return "21-50"
    else:
        return "50+"

def format_hit(ip, port, status, edition="Java"):
    if edition == "Bedrock":
        motd = status.motd
        version = status.version.version
        players_online = status.players_online
        players_max = status.players_max
        player_names = []
    else:
        motd = status.description
        if hasattr(motd, 'to_minecraft'):
            motd = motd.to_minecraft()
        else:
            motd = str(motd)
        version = status.version.name
        players_online = status.players.online
        players_max = status.players.max
        player_names = []
        if status.players.sample:
            player_names = [p.name for p in status.players.sample]

    line = f"[{edition.upper()}] {ip}:{port} | Ver: {version} | Players: {players_online}/{players_max} | MOTD: {motd}"
    if player_names:
        line += f" | Online: {', '.join(player_names)}"
    return line, version, players_online

def worker(task_queue, timeout, retries, use_proxy, save_bedrock, version_dir, players_dir, stop_event):
    global total_scanned, total_found, total_dead, total_errors
    while not stop_event.is_set():
        try:
            ip, port = task_queue.get(timeout=0.5)
        except queue.Empty:
            continue

        # Clear line and announce scanning
        with print_lock:
            sys.stdout.write('\033[2K\r')
            logger.log(f"scanning {ip}:{port}")

        status = None
        edition = None
        try:
            status = check_java_server(ip, port, timeout, retries, use_proxy)
            if status:
                edition = "Java"
            elif save_bedrock and port == 19132:
                status = check_bedrock_server(ip, port, timeout, retries, use_proxy)
                if status:
                    edition = "Bedrock"

            with counter_lock:
                total_scanned += 1
                if status:
                    total_found += 1
                else:
                    total_dead += 1

            # Clear line and print result
            with print_lock:
                sys.stdout.write('\033[2K\r')
                if status:
                    print(f"{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] {IvonColor.LIGHTBLACK}{ip}:{port} {IvonColor.GREEN}alive{IvonColor.RESET}")
                else:
                    print(f"{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] {IvonColor.LIGHTBLACK}{ip}:{port} {IvonColor.RED}dead{IvonColor.RESET}")

            if status:
                hit_str, ver_str, player_cnt = format_hit(ip, port, status, edition)

                # Version folder
                ver_folder = parse_version_string(ver_str)
                ver_path = os.path.join(version_dir, ver_folder)
                ensure_output_dir(ver_path)

                # Player folder
                player_folder = get_player_folder(player_cnt)
                player_path = os.path.join(players_dir, player_folder)
                ensure_output_dir(player_path)

                safe_ip = ip.replace('.', '_')
                filename = f"{safe_ip}_{port}.txt"

                # Save to version folder
                with open(os.path.join(ver_path, filename), 'w', encoding='utf-8') as f:
                    f.write(hit_str + '\n')

                # Save to player folder
                with open(os.path.join(player_path, filename), 'w', encoding='utf-8') as f:
                    f.write(hit_str + '\n')

                with print_lock:
                    sys.stdout.write('\033[2K\r')
                    logger.log(f"created file {filename}")

        except Exception as e:
            with counter_lock:
                total_errors += 1
            with print_lock:
                sys.stdout.write('\033[2K\r')
                logger.log(f"error {ip}:{port} - {e}")
        finally:
            task_queue.task_done()

def status_printer():
    while not status_stop.is_set():
        with counter_lock:
            dead_str = f"{total_dead:02d}" if total_dead < 100 else str(total_dead)
            alive_str = f"{total_found:02d}" if total_found < 100 else str(total_found)
            scanned_str = f"{total_scanned:02d}" if total_scanned < 100 else str(total_scanned)
            errors_str = f"{total_errors:02d}" if total_errors < 100 else str(total_errors)
            line = (f"{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] "
                    f"{IvonColor.LIGHTBLACK}{dead_str} dead {alive_str} alive "
                    f"{scanned_str} scanned {errors_str} errors{IvonColor.RESET}")
        with print_lock:
            sys.stdout.write('\033[2K\r' + line)
            sys.stdout.flush()
        time.sleep(STATUS_INTERVAL)

def generate_ips_from_ranges(ranges):
    for cidr in ranges:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            for ip in network.hosts():
                yield str(ip)
        except ValueError as e:
            print(f"Invalid CIDR '{cidr}': {e}", file=sys.stderr)

def print_banner():
    ascii_art = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣀⡿⠿⠿⠿⠿⠿⠿⢿⣀⣀⣀⣀⣀⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠸⠿⣇⣀⣀⣀⣀⣀⣀⣸⠿⢿⣿⣿⣿⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠻⠿⠿⠿⠿⠿⣿⣿⣀⡸⠿⢿⣿⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣤⣿⣿⣿⣧⣤⡼⠿⢧⣤⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣤⣿⣿⣿⣿⠛⢻⣿⡇⠀⢸⣿⡇
⠀⠀⠀⠀⠀⠀⠀⠀⣤⣤⣿⣿⣿⣿⠛⠛⠀⢸⣿⡇⠀⢸⣿⡇
⠀⠀⠀⠀⠀⠀⢠⣤⣿⣿⣿⣿⠛⠛⠀⠀⠀⢸⣿⡇⠀⢸⣿⡇
⠀⠀⠀⠀⢰⣶⣾⣿⣿⣿⠛⠛⠀⠀⠀⠀⠀⠈⠛⢳⣶⡞⠛⠁
⠀⠀⢰⣶⣾⣿⣿⣿⡏⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠁⠀⠀
⢰⣶⡎⠉⢹⣿⡏⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⣿⣷⣶⡎⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""
    lines = ascii_art.strip('\n').split('\n')
    start = "#cc00aa"
    end = "#03f8fc"
    for line in lines:
        GradientPrinter.gradient_print(line, start_color=start, end_color=end, end="\n")
    print(f"{IvonColor.LIGHTBLACK}made by ivonsify · vibecoded{IvonColor.RESET}\n")

# ==================== MAIN ====================
def main():
    # Interactive prompts
    try:
        threads_input = input(f"{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] {IvonColor.LIGHTBLACK}Enter number of threads (default 500): {IvonColor.RESET}").strip()
        threads = int(threads_input) if threads_input else 500

        bedrock_input = input(f"{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] {IvonColor.LIGHTBLACK}Include Bedrock? (y/n, default y): {IvonColor.RESET}").strip().lower()
        save_bedrock = bedrock_input != 'n'
    except KeyboardInterrupt:
        print("\nExiting.")
        return

    # Optional proxy file
    proxy_file = "proxies.txt"
    use_proxy = os.path.exists(proxy_file) and socks is not None
    global proxy_queue
    if use_proxy:
        provider = ProxyProvider(proxy_file)
        proxies = []
        while True:
            p = provider.get()
            if not p:
                break
            proxies.append(p)
        if proxies:
            proxy_queue = queue.Queue()
            for p in proxies:
                proxy_queue.put(p)
            print(f"{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] {IvonColor.LIGHTBLACK}Loaded {len(proxies)} proxies.{IvonColor.RESET}")
        else:
            use_proxy = False

    # Generate IPs
    ips = list(generate_ips_from_ranges(DEFAULT_RANGES))
    ports = DEFAULT_PORTS

    if not ips:
        print("No IP addresses to scan.")
        return

    total_ips = len(ips)
    total_tasks = total_ips * len(ports)

    # Create output directories
    run_dir, version_dir, players_dir = create_output_directories()

    # Print banner
    print_banner()

    print(f"{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] {IvonColor.LIGHTBLACK}Targets: {total_ips} IPs × {len(ports)} ports = {total_tasks} tasks{IvonColor.RESET}")
    print(f"{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] {IvonColor.LIGHTBLACK}Threads: {threads}  Timeout: 4s  Retries: 2{IvonColor.RESET}")
    if use_proxy:
        print(f"{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] {IvonColor.LIGHTBLACK}Proxy: Enabled{IvonColor.RESET}")
    print(f"{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] {IvonColor.LIGHTBLACK}Output directory: {run_dir}{IvonColor.RESET}")
    print(f"{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] {IvonColor.LIGHTBLACK}  → Version folders: versions/[VERSION]/{IvonColor.RESET}")
    print(f"{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] {IvonColor.LIGHTBLACK}  → Player folders: players/[COUNT]/\n{IvonColor.RESET}")

    # Fill task queue
    task_queue = queue.Queue()
    for ip in ips:
        for port in ports:
            task_queue.put((ip, port))

    # Title bar updater – no pipes!
    def title_stats():
        with counter_lock:
            return (f"ivon - Scanned:{total_scanned} Found:{total_found} "
                    f"Dead:{total_dead} Errors:{total_errors}")
    title_updater = TitleBarUpdater(title_stats, interval=0.5)
    title_updater.start()

    # Start workers
    stop_event = threading.Event()
    timeout, retries = 4, 2
    workers = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(task_queue, timeout, retries, use_proxy,
                                                   save_bedrock, version_dir, players_dir, stop_event))
        t.daemon = True
        t.start()
        workers.append(t)

    # Start status printer
    status_thread = threading.Thread(target=status_printer)
    status_thread.daemon = True
    status_thread.start()

    try:
        task_queue.join()
    except KeyboardInterrupt:
        print("\n\nReceived interrupt, shutting down...")
        stop_event.set()
    finally:
        status_stop.set()
        title_updater.stop()
        time.sleep(0.5)
        with counter_lock:
            dead_str = f"{total_dead:02d}" if total_dead < 100 else str(total_dead)
            alive_str = f"{total_found:02d}" if total_found < 100 else str(total_found)
            scanned_str = f"{total_scanned:02d}" if total_scanned < 100 else str(total_scanned)
            errors_str = f"{total_errors:02d}" if total_errors < 100 else str(total_errors)
            print(f"\n{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] {IvonColor.LIGHTBLACK}Final: {dead_str} dead {alive_str} alive {scanned_str} scanned {errors_str} errors{IvonColor.RESET}")
        print(f"{IvonColor.IVON}[{IvonColor.LIGHTBLACK}ivon{IvonColor.IVON}] {IvonColor.LIGHTBLACK}Hits saved to {run_dir}{IvonColor.RESET}")

if __name__ == "__main__":
    main()