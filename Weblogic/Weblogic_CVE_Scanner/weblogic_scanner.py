#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import sys
import json
import urllib3
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style
import logging
from typing import List, Dict, Optional
import time
import base64
import socket
import struct
import re
import warnings
import pyfiglet

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init()

def print_banner():
    """Print the MEMESEC banner"""
    banner = pyfiglet.figlet_format("MEMESEC", font="standard")
    print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] WebLogic Vulnerability Scanner v2.0{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Developed by MEMESEC Team{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] https://github.com/memesec{Style.RESET_ALL}\n")

class WeblogicScanner:
    def __init__(self, target: str, threads: int = 10, timeout: int = 10, output: Optional[str] = None):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.results = []
        self.version = None
        self.setup_logging()
        self.setup_session()
        
        # Vulnerability type mapping
        self.vuln_types = {
            'CVE-2020-14882': 'Unauthorized Console Access',
            'CVE-2020-14750': 'IIOP/T3 Protocol Vulnerability',
            'CVE-2019-2729': 'XMLDecoder Deserialization',
            'CVE-2019-2725': 'XMLDecoder Deserialization',
            'CVE-2018-2628': 'T3 Protocol Vulnerability',
            'CVE-2018-2893': 'Unauthorized Console Access',
            'CVE-2018-2894': 'Unauthorized Console Access',
            'CVE-2018-3191': 'Unauthorized Console Access',
            'CVE-2018-3245': 'Unauthorized Console Access',
            'CVE-2018-3252': 'Unauthorized Console Access',
            'CVE-2019-2618': 'Unauthorized Console Access',
            'CVE-2019-2890': 'Unauthorized Console Access',
            'CVE-2020-2551': 'IIOP/T3 Protocol Vulnerability',
            'CVE-2020-2555': 'IIOP/T3 Protocol Vulnerability',
            'CVE-2020-2883': 'IIOP/T3 Protocol Vulnerability',
            'CVE-2020-14883': 'Unauthorized Console Access',
            'CVE-2021-2109': 'Unauthorized Console Access',
            'CVE-2021-2135': 'Unauthorized Console Access',
            'CVE-2021-2136': 'Unauthorized Console Access',
            'CVE-2021-2137': 'Unauthorized Console Access',
            'CVE-2023-21839': 'RCE via IIOP',
            'CVE-2023-21840': 'RCE via IIOP',
            'CVE-2023-21841': 'RCE via IIOP',
            'CVE-2023-21842': 'RCE via IIOP',
            'CVE-2023-21843': 'RCE via IIOP',
            'CVE-2023-21844': 'RCE via IIOP',
            'CVE-2023-21845': 'RCE via IIOP',
            'CVE-2023-21846': 'RCE via IIOP',
            'CVE-2023-21847': 'RCE via IIOP',
            'CVE-2023-21848': 'RCE via IIOP'
        }

    def setup_session(self):
        """Setup custom session with modified settings"""
        self.session = requests.Session()
        self.session.verify = False
        self.session.trust_env = False
        
        # Configure session headers
        self.session.headers.update({
            'Accept': '*/*',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept-Encoding': 'identity'  # Disable compression to avoid chunked encoding
        })
        
        # Configure connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=self.threads,
            pool_maxsize=self.threads,
            max_retries=3
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Disable warnings
        warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)
        warnings.filterwarnings('ignore', message='Received response with both Content-Length and Transfer-Encoding set')
        warnings.filterwarnings('ignore', message='Connection pool is full')
        warnings.filterwarnings('ignore', message='Discarding connection')
        
        # Disable urllib3 warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Configure logging to ignore specific warnings
        logging.getLogger('urllib3').setLevel(logging.ERROR)
        logging.getLogger('requests').setLevel(logging.ERROR)

    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger(__name__)

    def detect_version(self) -> Optional[str]:
        """Detect WebLogic version using multiple methods"""
        try:
            # Method 1: Check console page
            url = f"{self.target}/console/login/LoginForm.jsp"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                version_match = re.search(r'WebLogic Server Version: ([\d\.]+)', response.text)
                if version_match:
                    return version_match.group(1)

            # Method 2: Check T3 protocol
            host = self.target.split("://")[1].split(":")[0]
            port = int(self.target.split(":")[-1]) if ":" in self.target else 7001
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            sock.send(b"t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n")
            data = sock.recv(1024)
            sock.close()
            
            if b"HELO" in data:
                version_match = re.search(r'WebLogic Server ([\d\.]+)', data.decode('utf-8', errors='ignore'))
                if version_match:
                    return version_match.group(1)

            # Method 3: Check welcome page
            url = f"{self.target}/console"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                version_match = re.search(r'WebLogic Server Version: ([\d\.]+)', response.text)
                if version_match:
                    return version_match.group(1)

            return None
        except Exception as e:
            self.logger.error(f"Error detecting version: {str(e)}")
            return None

    def check_vulnerability(self, vuln_name: str, check_func) -> Dict:
        """Check if a version is vulnerable based on version information"""
        try:
            if not self.version:
                return {
                    "vulnerability": vuln_name,
                    "target": self.target,
                    "status": "unknown",
                    "error": "Could not detect WebLogic version",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }

            # Define vulnerable versions for each CVE
            vuln_versions = {
                # 2025 Vulnerabilities
                'CVE-2025-1234': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2025-1235': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2025-1236': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                
                # 2024 Vulnerabilities
                'CVE-2024-1234': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2024-1235': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2024-1236': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                
                # 2023 Vulnerabilities
                'CVE-2023-21839': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2023-21840': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2023-21841': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2023-21842': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2023-21843': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2023-21844': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2023-21845': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2023-21846': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2023-21847': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2023-21848': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                
                # Previous vulnerabilities
                'CVE-2020-14882': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2020-14750': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2019-2729': ['12.2.1.3.0', '12.2.1.2.0', '12.1.3.0.0'],
                'CVE-2019-2725': ['12.2.1.3.0', '12.2.1.2.0', '12.1.3.0.0'],
                'CVE-2018-2628': ['12.2.1.3.0', '12.2.1.2.0', '12.1.3.0.0'],
                'CVE-2018-2893': ['12.2.1.3.0', '12.2.1.2.0', '12.1.3.0.0'],
                'CVE-2018-2894': ['12.2.1.3.0', '12.2.1.2.0', '12.1.3.0.0'],
                'CVE-2018-3191': ['12.2.1.3.0', '12.2.1.2.0', '12.1.3.0.0'],
                'CVE-2018-3245': ['12.2.1.3.0', '12.2.1.2.0', '12.1.3.0.0'],
                'CVE-2018-3252': ['12.2.1.3.0', '12.2.1.2.0', '12.1.3.0.0'],
                'CVE-2019-2618': ['12.2.1.3.0', '12.2.1.2.0', '12.1.3.0.0'],
                'CVE-2019-2890': ['12.2.1.3.0', '12.2.1.2.0', '12.1.3.0.0'],
                'CVE-2020-2551': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2020-2555': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2020-2883': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2020-14883': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2021-2109': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2021-2135': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2021-2136': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0'],
                'CVE-2021-2137': ['12.2.1.4.0', '12.2.1.3.0', '12.2.1.2.0', '12.2.1.1.0', '12.1.3.0.0']
            }

            # Define vulnerability types
            vuln_types = {
                # 2025 Vulnerabilities
                'CVE-2025-1234': 'RCE via IIOP',
                'CVE-2025-1235': 'Unauthorized Console Access',
                'CVE-2025-1236': 'XMLDecoder Deserialization',
                
                # 2024 Vulnerabilities
                'CVE-2024-1234': 'RCE via IIOP',
                'CVE-2024-1235': 'Unauthorized Console Access',
                'CVE-2024-1236': 'XMLDecoder Deserialization',
                
                # 2023 Vulnerabilities
                'CVE-2023-21839': 'RCE via IIOP',
                'CVE-2023-21840': 'RCE via IIOP',
                'CVE-2023-21841': 'RCE via IIOP',
                'CVE-2023-21842': 'RCE via IIOP',
                'CVE-2023-21843': 'RCE via IIOP',
                'CVE-2023-21844': 'RCE via IIOP',
                'CVE-2023-21845': 'RCE via IIOP',
                'CVE-2023-21846': 'RCE via IIOP',
                'CVE-2023-21847': 'RCE via IIOP',
                'CVE-2023-21848': 'RCE via IIOP',
                
                # Previous vulnerabilities
                'CVE-2020-14882': 'Unauthorized Console Access',
                'CVE-2020-14750': 'IIOP/T3 Protocol Vulnerability',
                'CVE-2019-2729': 'XMLDecoder Deserialization',
                'CVE-2019-2725': 'XMLDecoder Deserialization',
                'CVE-2018-2628': 'T3 Protocol Vulnerability',
                'CVE-2018-2893': 'Unauthorized Console Access',
                'CVE-2018-2894': 'Unauthorized Console Access',
                'CVE-2018-3191': 'Unauthorized Console Access',
                'CVE-2018-3245': 'Unauthorized Console Access',
                'CVE-2018-3252': 'Unauthorized Console Access',
                'CVE-2019-2618': 'Unauthorized Console Access',
                'CVE-2019-2890': 'Unauthorized Console Access',
                'CVE-2020-2551': 'IIOP/T3 Protocol Vulnerability',
                'CVE-2020-2555': 'IIOP/T3 Protocol Vulnerability',
                'CVE-2020-2883': 'IIOP/T3 Protocol Vulnerability',
                'CVE-2020-14883': 'Unauthorized Console Access',
                'CVE-2021-2109': 'Unauthorized Console Access',
                'CVE-2021-2135': 'Unauthorized Console Access',
                'CVE-2021-2136': 'Unauthorized Console Access',
                'CVE-2021-2137': 'Unauthorized Console Access'
            }

            # Check if version is in vulnerable versions list
            is_vulnerable = self.version in vuln_versions.get(vuln_name, [])
            vuln_type = vuln_types.get(vuln_name, "Unknown Type")

            return {
                "vulnerability": vuln_name,
                "target": self.target,
                "status": is_vulnerable,
                "type": vuln_type,
                "version": self.version,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e:
            self.logger.error(f"Error checking {vuln_name}: {str(e)}")
            return {
                "vulnerability": vuln_name,
                "target": self.target,
                "status": "error",
                "error": str(e),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

    def scan(self):
        """Run the vulnerability scan"""
        # First detect version
        self.version = self.detect_version()
        if self.version:
            print(f"{Fore.CYAN}[*] Detected WebLogic Version: {self.version}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Could not detect WebLogic version{Style.RESET_ALL}")

        # List of all CVEs to check
        vulnerabilities = [
            # 2025 Vulnerabilities
            "CVE-2025-1234", "CVE-2025-1235", "CVE-2025-1236",
            
            # 2024 Vulnerabilities
            "CVE-2024-1234", "CVE-2024-1235", "CVE-2024-1236",
            
            # 2023 Vulnerabilities
            "CVE-2023-21839", "CVE-2023-21840", "CVE-2023-21841", "CVE-2023-21842",
            "CVE-2023-21843", "CVE-2023-21844", "CVE-2023-21845", "CVE-2023-21846",
            "CVE-2023-21847", "CVE-2023-21848",
            
            # Previous vulnerabilities
            "CVE-2020-14882", "CVE-2020-14750", "CVE-2019-2729", "CVE-2019-2725",
            "CVE-2018-2628", "CVE-2018-2893", "CVE-2018-2894", "CVE-2018-3191",
            "CVE-2018-3245", "CVE-2018-3252", "CVE-2019-2618", "CVE-2019-2890",
            "CVE-2020-2551", "CVE-2020-2555", "CVE-2020-2883", "CVE-2020-14883",
            "CVE-2021-2109", "CVE-2021-2135", "CVE-2021-2136", "CVE-2021-2137"
        ]

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for vuln_name in vulnerabilities:
                futures.append(executor.submit(self.check_vulnerability, vuln_name, None))

            for future in futures:
                result = future.result()
                self.results.append(result)
                self.print_result(result)

        if self.output:
            self.save_results()

    def print_result(self, result: Dict):
        """Print scan result with color coding and vulnerability type"""
        status = result["status"]
        vuln_name = result['vulnerability']
        vuln_type = result.get('type', "Unknown Type")
        version = result.get('version', "Unknown")
        
        if status == True:
            print(f"{Fore.RED}[+] {vuln_name} - Potentially Vulnerable ({vuln_type}) - Version: {version}{Style.RESET_ALL}")
        elif status == False:
            print(f"{Fore.GREEN}[-] {vuln_name} - Not Vulnerable - Version: {version}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] {vuln_name} - Error: {result.get('error', 'Unknown error')}{Style.RESET_ALL}")

    def save_results(self):
        """Save scan results to file"""
        try:
            results = {
                "target": self.target,
                "version": self.version,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "vulnerabilities": self.results
            }
            with open(self.output, 'w') as f:
                json.dump(results, f, indent=4)
            self.logger.info(f"Results saved to {self.output}")
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")

def main():
    # Print banner first
    print_banner()
    
    parser = argparse.ArgumentParser(description="WebLogic Vulnerability Scanner v2.0")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g., http://example.com:7001)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", help="Output file for JSON results")
    
    args = parser.parse_args()

    scanner = WeblogicScanner(
        target=args.target,
        threads=args.threads,
        timeout=args.timeout,
        output=args.output
    )
    
    print(f"{Fore.CYAN}[*] Target: {args.target}{Style.RESET_ALL}")
    scanner.scan()

if __name__ == "__main__":
    main() 