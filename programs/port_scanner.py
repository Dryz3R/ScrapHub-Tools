import socket, threading, json, os, time, platform
import ipaddress, requests
from datetime import datetime
from colorama import Fore, Style
from scapy.all import sniff, IP, TCP, UDP

def packet_sniffer(duration=20):
    print(f"{Fore.MAGENTA}[INFO] Packet sniffing activé pour {duration} secondes...{Style.RESET_ALL}")
    packets = sniff(timeout=duration)
    print(f"{Fore.MAGENTA}[INFO] {len(packets)} paquets capturés.{Style.RESET_ALL}")
    return packets

def get_whois(ip):
    try:
        r = requests.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=3)
        if r.status_code == 200: return r.json()
    except: pass
    return {}

def banner_grab(ip, port, proto='TCP', timeout=1):
    try:
        if proto == 'TCP':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.send(b"\r\n")
            return s.recv(1024).decode(errors='ignore').strip()
    except: return ""
    return ""

def os_guess(ip):
    try:
        ttl = None
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, 80))
        ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        s.close()
        if ttl: return "Linux" if ttl <= 64 else "Windows" if ttl <= 128 else "Unknown"
    except: return "Unknown"
    return "Unknown"

def scan_target(target):
    try:
        ip = socket.gethostbyname(target)
    except: ip = target

    tcp_ports = [21,22,23,25,53,80,110,143,443,3306,3389,8080]
    udp_ports = [53,67,68,123,161,500,514,520,4500]
    timeout = 1.0
    threads = min(50, len(tcp_ports)+len(udp_ports))
    open_ports = []

    lock = threading.Lock()
    print(f"{Fore.YELLOW}[INFO] Scan TCP & UDP de {target} ({ip}){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}=================================================={Style.RESET_ALL}")

    def scan_port(port, proto='TCP'):
        status = 'CLOSED'
        banner = ''
        try:
            if proto == 'TCP':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    status = 'OPEN'
                    banner = banner_grab(ip, port)
                s.close()
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                s.sendto(b"\x00", (ip, port))
                try:
                    s.recvfrom(1024)
                    status = 'OPEN'
                except: pass
                s.close()
        except: pass
        with lock:
            open_ports.append({'port': port, 'proto': proto, 'status': status, 'banner': banner})
            color = Fore.GREEN if status=='OPEN' else Fore.RED
            print(f"{color}[{status}] {proto} Port {port} Banner: {banner}{Style.RESET_ALL}")

    thread_pool = []
    for p in tcp_ports: thread_pool.append(threading.Thread(target=scan_port, args=(p,'TCP')))
    for p in udp_ports: thread_pool.append(threading.Thread(target=scan_port, args=(p,'UDP')))

    for t in thread_pool:
        t.start()
        if threading.active_count() > threads: time.sleep(0.01)
    for t in thread_pool: t.join()

    whois_data = get_whois(ip)
    guess_os = os_guess(ip)
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    output = {
        'target': target,
        'resolved_ip': ip,
        'scan_time': scan_time,
        'os_guess': guess_os,
        'ports': open_ports,
        'whois': whois_data
    }

    out_dir = os.path.join('output','Port Scanner', target)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, f'{target}.txt'), 'w', encoding='utf-8') as f:
        f.write(json.dumps(output, indent=2))
    with open(os.path.join(out_dir, f'{target}.json'), 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)

    print(f"{Fore.CYAN}[INFO] Scan terminé. Résultats exportés dans {out_dir}{Style.RESET_ALL}")
    packet_sniffer(duration=10)

if __name__ == "__main__":
    target = input(f"{Fore.WHITE}IP ou hostname cible : {Style.RESET_ALL}")
    scan_target(target)
