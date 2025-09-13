import socket
import threading
import time
from colorama import Fore, Style

def port_scanner():
    target = input(f"{Fore.WHITE}Enter target IP or hostname: {Style.RESET_ALL}")
    start_port = int(input(f"{Fore.WHITE}Start port: {Style.RESET_ALL}"))
    end_port = int(input(f"{Fore.WHITE}End port: {Style.RESET_ALL}"))
    timeout = float(input(f"{Fore.WHITE}Timeout (seconds): {Style.RESET_ALL}"))
    threads = int(input(f"{Fore.WHITE}Number of threads: {Style.RESET_ALL}"))

    print(f"\n{Fore.YELLOW}Scanning {target} from port {start_port} to {end_port}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}=================================================={Style.RESET_ALL}")

    open_ports = []
    lock = threading.Lock()

    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                with lock:
                    open_ports.append(port)
                    print(f"{Fore.GREEN}Port {port}: OPEN{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Port {port}: CLOSED{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}Port {port}: ERROR - {e}{Style.RESET_ALL}")

    start_time = time.time()
    
    thread_pool = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(port,))
        thread_pool.append(thread)
        thread.start()
        
        if len(thread_pool) >= threads:
            for t in thread_pool:
                t.join()
            thread_pool = []

    for thread in thread_pool:
        thread.join()

    end_time = time.time()
    
    print(f"\n{Fore.YELLOW}=================================================={Style.RESET_ALL}")
    print(f"{Fore.CYAN}Scan completed in {end_time - start_time:.2f} seconds{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Open ports found: {len(open_ports)}{Style.RESET_ALL}")
    
    if open_ports:
        print(f"{Fore.CYAN}Open ports: {sorted(open_ports)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.WHITE}Press Enter to return to main menu...{Style.RESET_ALL}")

if __name__ == "__main__":
    port_scanner()