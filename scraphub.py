import os
import sys
import time
import subprocess
from colorama import Fore, Style, init

init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = f"""{Fore.RED}
  ██████  ▄████▄   ██▀███   ▄▄▄       ██▓███   ██░ ██  █    ██  ▄▄▄▄   
▒██    ▒ ▒██▀ ▀█  ▓██ ▒ ██▒▒████▄    ▓██░  ██▒▓██░ ██▒ ██  ▓██▒▓█████▄ 
░ ▓██▄   ▒▓█    ▄ ▓██ ░▄█ ▒▒██  ▀█▄  ▓██░ ██▓▒▒██▀▀██░▓██  ▒██░▒██▒ ▄██
  ▒   ██▒▒▓▓▄ ▄██▒▒██▀▀█▄  ░██▄▄▄▄██ ▒██▄█▓▒ ▒░▓█ ░██ ▓▓█  ░██░▒██░█▀  
▒██████▒▒▒ ▓███▀ ░░██▓ ▒██▒ ▓█   ▓██▒▒██▒ ░  ░░▓█▒░██▓▒▒█████▓ ░▓█  ▀█▓
▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░▒▓▒░ ░  ░ ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░▒▓███▀▒
░ ░▒  ░ ░  ░  ▒     ░▒ ░ ▒░  ▒   ▒▒ ░░▒ ░      ▒ ░▒░ ░░░▒░ ░ ░ ▒░▒   ░ 
░  ░  ░  ░          ░░   ░   ░   ▒   ░░        ░  ░░ ░ ░░░ ░ ░  ░    ░ 
      ░  ░ ░         ░           ░  ░          ░  ░  ░   ░      ░      
         ░                                                           ░ 
{Style.RESET_ALL}"""
    print(banner)

def print_menu_page(page):
    pages = [
        [
            ["PENTESTING TOOLS", [
                "1. Port Scanner",
                "2. Vulnerability Analysis", 
                "3. Service Exploitation",
                "4. Website DoS"
            ]],
            ["NETWORK TOOLS", [
                "5. Traffic Analysis",
                "6. Advanced Traceroute",
                "7. IP/Subnet Scanner"
            ]]
        ],
        [
            ["WEB TOOLS", [
                "8. Advanced Web Research",
                "9. Public Data Analysis",
                "10. Data Breach Check",
                "11. Exposed Files Analysis"
            ]],
            ["SECURITY TOOLS", [
                "12. Vulnerability Report", 
                "13. DOS Attack",
                "14. SQL Injection",
                "15. XSS Attack"
            ]]
        ],
        [
            ["DISCORD TOOLS", [
                "16. Server Analysis",
                "17. Self Bot", 
                "18. ID Lookup",
                "19. ID Logs",
                "20. Token Info",
                "21. Token Nuker"
            ]],
            ["PASSWORD TOOLS", [
                "22. ZIP/RAR Cracker",
                "23. Password Decrypt",
                "24. Password Encrypt"
            ]]
        ],
        [
            ["ADVANCED TOOLS", [
                "25. Token Joiner",
                "26. Token Leaver", 
                "27. Token Login",
                "28. Token to ID & Brute",
                "29. Nitro Generator"
            ]],
            ["OTHER TOOLS", [
                "30. Cookie Login",
                "31. Cookie Info",
                "32. Get Image EXIF 1",
                "33. Get Image EXIF 2",
                "34. Get Image EXIF 3",
                "35. Python Obfuscator"
            ]]
        ],
        [
            ["ADDITIONAL OPTIONS", [
                "36. Info",
                "37. Site (unavailable)",
                "38. Discord"
            ]]
        ]
    ]
    
    if page < len(pages):
        columns = pages[page]
        max_lines = max(len(col[1]) for col in columns)
        
        for i in range(max_lines):
            line = ""
            for col_idx, col in enumerate(columns):
                category, items = col
                if i == 0:
                    if col_idx > 0:
                        line += " " * 5
                    line += f"{Fore.RED}{category:<25}{Style.RESET_ALL}"
                else:
                    if col_idx > 0:
                        line += " " * 5
                    if i-1 < len(items):
                        line += f"{Fore.WHITE}{items[i-1]:<25}{Style.RESET_ALL}"
                    else:
                        line += " " * 25
            print(line)

def run_script(script_name):
    try:
        script_path = os.path.join("programs", script_name)
        if os.path.exists(script_path):
            subprocess.run([sys.executable, script_path])
        else:
            print(f"Script {script_name} not found")
            time.sleep(2)
    except Exception as e:
        print(f"Error: {e}")
        time.sleep(2)

def main():
    current_page = 0
    total_pages = 5
    
    while True:
        clear_screen()
        print_banner()
        print(f"\n{Fore.WHITE}Page {current_page + 1}/{total_pages}")
        print_menu_page(current_page)
        
        print(f"\n{Fore.WHITE}n: Next page | b: Previous page")
        print("number: Select option | q: Quit")
        
        choice = input(f"\n{Fore.WHITE}➤ ").lower()
        
        if choice == 'n':
            current_page = (current_page + 1) % total_pages
        elif choice == 'b':
            current_page = (current_page - 1) % total_pages
        elif choice == 'q':
            clear_screen()
            sys.exit()
        elif choice.isdigit():
            option = int(choice)
            script_map = {
                1: "port_scanner.py",
                2: "vuln_scanner.py",
                3: "exploit_service.py",
                4: "website_dos.py",
                5: "analyse_trafic.py",
                6: "traceroute_avance.py",
                7: "scan_ip_subnets.py",
                8: "recherche_web.py",
                9: "analyse_donnees_publiques.py",
                10: "data_breach.py",
                11: "file_analyse.py",
                12: "vuln_rapport.py",
                13: "dos_attack.py",
                14: "sqli_attack.py",
                15: "xss_attack.py",
                16: "analyse_serveurs.py",
                17: "self_bot.py",
                18: "id_lookup.py",
                19: "id_logs.py",
                20: "token_info.py",
                21: "token_nuker.py",
                22: "zip_cracked.py",
                23: "password_decrypted.py",
                24: "password_encrypt.py",
                25: "token_joiner.py",
                26: "token_leaver.py",
                27: "token_login.py",
                28: "token_to_id_brute.py",
                29: "nitro_generator.py",
                30: "roblox_cookie_login.py",
                31: "roblox_cookie_info.py",
                32: "get_image_exif1.py",
                33: "get_image_exif2.py",
                34: "get_image_exif3.py",
                35: "python_obfuscator.py",
                36: "info.py",
                37: "site.py",
                38: "discord.py"
            }
            if option in script_map:
                run_script(script_map[option])
            else:
                print(f"Option {option} not available")
                time.sleep(1)

if __name__ == "__main__":
    main()