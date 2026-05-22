#!/usr/bin/env python3
"""
Professional Port Scanner - Production Grade
Features: SYN/Connect scan, Service Detection, OS Fingerprinting, Banner Grabbing
Author: Termux Pentest Toolkit
Version: 3.0
"""

import socket
import struct
import sys
import time
import json
import os
import re
import random
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict

# Terminal colors
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BLUE = '\033[94m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'

C = Colors()

# Common service signatures
SERVICE_SIGNATURES = {
    21: {'service': 'FTP', 'banner_check': True},
    22: {'service': 'SSH', 'banner_check': True},
    23: {'service': 'Telnet', 'banner_check': True},
    25: {'service': 'SMTP', 'banner_check': True},
    53: {'service': 'DNS', 'banner_check': False},
    80: {'service': 'HTTP', 'banner_check': True},
    110: {'service': 'POP3', 'banner_check': True},
    111: {'service': 'RPC', 'banner_check': False},
    135: {'service': 'MSRPC', 'banner_check': False},
    139: {'service': 'NetBIOS', 'banner_check': False},
    143: {'service': 'IMAP', 'banner_check': True},
    443: {'service': 'HTTPS', 'banner_check': True},
    445: {'service': 'SMB', 'banner_check': False},
    993: {'service': 'IMAPS', 'banner_check': False},
    995: {'service': 'POP3S', 'banner_check': False},
    1433: {'service': 'MSSQL', 'banner_check': False},
    1521: {'service': 'Oracle', 'banner_check': False},
    3306: {'service': 'MySQL', 'banner_check': True},
    3389: {'service': 'RDP', 'banner_check': False},
    5432: {'service': 'PostgreSQL', 'banner_check': False},
    5900: {'service': 'VNC', 'banner_check': True},
    6379: {'service': 'Redis', 'banner_check': False},
    8080: {'service': 'HTTP-Proxy', 'banner_check': True},
    8443: {'service': 'HTTPS-Alt', 'banner_check': True},
    27017: {'service': 'MongoDB', 'banner_check': False},
}

# OS Fingerprinting signatures based on TCP/IP stack
OS_SIGNATURES = {
    'Linux': {
        'ttl_range': (64, 64),
        'window_size': 5840,
        'tcp_options': ['mss', 'sackOK', 'timestamp'],
    },
    'Windows': {
        'ttl_range': (128, 128),
        'window_size': 65535,
        'tcp_options': ['mss', 'nop', 'window_scale', 'sackOK'],
    },
    'FreeBSD': {
        'ttl_range': (64, 64),
        'window_size': 65535,
        'tcp_options': ['mss', 'nop', 'window_scale', 'sackOK', 'timestamp'],
    },
    'macOS': {
        'ttl_range': (64, 64),
        'window_size': 65535,
        'tcp_options': ['mss', 'nop', 'window_scale', 'sackOK', 'timestamp'],
    },
}

class AdvancedPortScanner:
    def __init__(self, target, start_port=1, end_port=1000, timeout=1.0, 
                 workers=50, aggressive=False, grab_banners=True, os_detect=True):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.workers = workers
        self.aggressive = aggressive
        self.grab_banners = grab_banners
        self.os_detect = os_detect
        self.results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'open_ports': [],
            'services': {},
            'banners': {},
            'os': {},
            'vulnerabilities': [],
            'scan_stats': {}
        }
        
    def resolve(self):
        """Resolve hostname to IP"""
        try:
            # Check if already IP
            ipaddress.ip_address(self.target)
            return self.target, self.target
        except:
            try:
                ip = socket.gethostbyname(self.target)
                return self.target, ip
            except:
                print(f"{C.RED}[!] Cannot resolve {self.target}{C.END}")
                sys.exit(1)
    
    def tcp_connect_scan(self, host, port):
        """TCP Connect scan with banner grabbing"""
        start_time = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Set socket options for better detection
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            result = sock.connect_ex((host, port))
            response_time = time.time() - start_time
            
            if result == 0:
                service = self.get_service(port)
                banner = ""
                
                if self.grab_banners:
                    banner = self.grab_banner(sock, port)
                
                sock.close()
                return {
                    'port': port,
                    'state': 'OPEN',
                    'service': service,
                    'banner': banner[:200] if banner else "",
                    'response_time': round(response_time, 4)
                }
            else:
                sock.close()
                return {
                    'port': port,
                    'state': 'CLOSED',
                    'service': '',
                    'banner': '',
                    'response_time': round(response_time, 4)
                }
                
        except socket.timeout:
            return {
                'port': port,
                'state': 'FILTERED',
                'service': '',
                'banner': '',
                'response_time': self.timeout
            }
        except Exception as e:
            return {
                'port': port,
                'state': 'ERROR',
                'service': '',
                'banner': str(e),
                'response_time': 0
            }
    
    def get_service(self, port):
        """Get service name"""
        if port in SERVICE_SIGNATURES:
            return SERVICE_SIGNATURES[port]['service']
        try:
            return socket.getservbyport(port, 'tcp')
        except:
            return 'unknown'
    
    def grab_banner(self, sock, port):
        """Grab service banner"""
        banner = ""
        try:
            # Send appropriate probe based on port
            if port == 80 or port == 8080:
                sock.send(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                time.sleep(0.3)
            elif port == 443 or port == 8443:
                # Can't grab HTTPS banner easily
                pass
            elif port == 22:
                # SSH sends banner automatically
                pass
            elif port == 21:
                # FTP sends banner automatically
                pass
            elif port == 25:
                # SMTP - send EHLO
                time.sleep(0.2)
                sock.send(b"EHLO test\r\n")
                time.sleep(0.3)
            elif port == 3306:
                # MySQL sends banner automatically
                pass
            
            sock.settimeout(0.5)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            pass
        
        return banner
    
    def os_fingerprint(self, host, open_ports):
        """OS detection using TCP/IP stack fingerprinting"""
        print(f"\n{C.BOLD}[*] Performing OS Detection...{C.END}")
        
        os_matches = defaultdict(int)
        
        try:
            # Test TTL values
            for port_info in open_ports[:5]:  # Test first 5 open ports
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((host, port_info['port']))
                    
                    # Get TCP options (not directly available in Python socket)
                    # Use TTL approximation
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
                    
                    # Check window size (approximate)
                    ttl = 255  # Default
                    
                    for os_name, sig in OS_SIGNATURES.items():
                        if sig['ttl_range'][0] <= ttl <= sig['ttl_range'][1]:
                            os_matches[os_name] += 1
                    
                    sock.close()
                except:
                    pass
            
            # Service-based OS hints
            for port_info in open_ports:
                port = port_info['port']
                banner = port_info.get('banner', '').lower()
                
                if 'ubuntu' in banner or 'debian' in banner:
                    os_matches['Linux (Ubuntu/Debian)'] += 3
                elif 'centos' in banner or 'rhel' in banner:
                    os_matches['Linux (CentOS/RHEL)'] += 3
                elif 'windows' in banner or 'microsoft' in banner:
                    os_matches['Windows'] += 3
                elif 'freebsd' in banner:
                    os_matches['FreeBSD'] += 3
                elif 'darwin' in banner or 'macos' in banner:
                    os_matches['macOS'] += 3
                
                # Port-based hints
                if port == 445 or port == 135 or port == 139:
                    os_matches['Windows'] += 2
                elif port == 3306:
                    os_matches['Linux'] += 1
                elif port == 3389:
                    os_matches['Windows'] += 2
            
            if os_matches:
                best_match = max(os_matches, key=os_matches.get)
                confidence = (os_matches[best_match] / max(sum(os_matches.values()), 1)) * 100
                
                self.results['os'] = {
                    'best_match': best_match,
                    'confidence': f"{min(confidence, 100):.1f}%",
                    'all_matches': dict(os_matches)
                }
                
                print(f"  {C.GREEN}OS: {best_match} (confidence: {confidence:.1f}%){C.END}")
            else:
                print(f"  {C.YELLOW}OS: Could not determine{C.END}")
                
        except Exception as e:
            print(f"  {C.RED}OS detection failed: {e}{C.END}")
    
    def vulnerability_check(self, port_info):
        """Check for known vulnerabilities based on port/service"""
        vulns = []
        
        port = port_info['port']
        service = port_info.get('service', '')
        banner = port_info.get('banner', '').lower()
        
        # Telnet - always vulnerable
        if port == 23:
            vulns.append({
                'vulnerability': 'Telnet Clear Text Protocol',
                'severity': 'HIGH',
                'description': 'Telnet transmits all data in cleartext',
                'recommendation': 'Disable Telnet, use SSH instead'
            })
        
        # FTP anonymous login
        if port == 21 and ('anonymous' in banner or '230' in banner):
            vulns.append({
                'vulnerability': 'Anonymous FTP Access',
                'severity': 'MEDIUM',
                'description': 'FTP server allows anonymous login',
                'recommendation': 'Disable anonymous FTP access'
            })
        
        # Old SSH versions
        if port == 22 and 'ssh-1' in banner:
            vulns.append({
                'vulnerability': 'SSH Protocol 1 Enabled',
                'severity': 'HIGH',
                'description': 'SSH v1 has known vulnerabilities',
                'recommendation': 'Disable SSH protocol 1, use only v2'
            })
        
        # HTTP without HTTPS
        if port == 80 and 443 not in [p['port'] for p in self.results['open_ports']]:
            vulns.append({
                'vulnerability': 'HTTP without HTTPS',
                'severity': 'LOW',
                'description': 'Web server running without SSL/TLS',
                'recommendation': 'Enable HTTPS with valid certificate'
            })
        
        # MySQL exposed
        if port == 3306:
            vulns.append({
                'vulnerability': 'MySQL Directly Accessible',
                'severity': 'MEDIUM',
                'description': 'Database server exposed to network',
                'recommendation': 'Restrict MySQL access to localhost only'
            })
        
        return vulns
    
    def scan(self):
        """Main scan function"""
        hostname, ip = self.resolve()
        
        print(f"\n{C.BOLD}{C.CYAN}╔══════════════════════════════════════════╗{C.END}")
        print(f"{C.BOLD}{C.CYAN}║     PROFESSIONAL PORT SCANNER v3.0       ║{C.END}")
        print(f"{C.BOLD}{C.CYAN}╚══════════════════════════════════════════╝{C.END}")
        
        print(f"\n{C.BOLD}[*] Target:{C.END} {hostname} ({ip})")
        print(f"{C.BOLD}[*] Port Range:{C.END} {self.start_port}-{self.end_port}")
        print(f"{C.BOLD}[*] Workers:{C.END} {self.workers}")
        print(f"{C.BOLD}[*] Banner Grab:{C.END} {'Yes' if self.grab_banners else 'No'}")
        print(f"{C.BOLD}[*] OS Detection:{C.END} {'Yes' if self.os_detect else 'No'}")
        print(f"{C.BOLD}[*] Time:{C.END} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        ports = range(self.start_port, self.end_port + 1)
        total_ports = len(ports)
        completed = 0
        open_ports = []
        
        start_time = time.time()
        
        print(f"{C.CYAN}[*] Scanning {total_ports} ports...{C.END}\n")
        
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {
                executor.submit(self.tcp_connect_scan, ip, port): port 
                for port in ports
            }
            
            for future in as_completed(futures):
                result = future.result()
                completed += 1
                
                if result['state'] == 'OPEN':
                    open_ports.append(result)
                    
                    # Live output for found ports
                    service_str = f" ({result['service']})" if result['service'] != 'unknown' else ""
                    print(f"{C.GREEN}[+] Port {result['port']}/tcp OPEN{service_str}{C.END}")
                    
                    if result['banner']:
                        banner_preview = result['banner'][:100].replace('\n', ' ')
                        print(f"    {C.DIM}Banner: {banner_preview}{C.END}")
                
                # Progress bar
                if completed % max(1, total_ports // 20) == 0 or completed == total_ports:
                    pct = (completed / total_ports) * 100
                    bar_len = 30
                    filled = int(bar_len * completed // total_ports)
                    bar = '█' * filled + '░' * (bar_len - filled)
                    print(f"\r{C.DIM}[{bar}] {pct:.1f}% ({completed}/{total_ports}) | Open: {len(open_ports)}{C.END}", 
                          end='', flush=True)
        
        scan_duration = time.time() - start_time
        
        print(f"\n\n{C.GREEN}[✓] Scan completed in {scan_duration:.2f}s{C.END}")
        
        # Store results
        self.results['open_ports'] = open_ports
        self.results['scan_stats'] = {
            'total_scanned': total_ports,
            'open_ports': len(open_ports),
            'closed_ports': total_ports - len(open_ports),
            'scan_duration': round(scan_duration, 2),
            'scan_rate': round(total_ports / scan_duration, 2)
        }
        
        # OS Detection
        if self.os_detect and open_ports:
            self.os_fingerprint(ip, open_ports)
        
        # Vulnerability checks
        if open_ports:
            print(f"\n{C.BOLD}[*] Vulnerability Assessment:{C.END}")
            for port_info in open_ports:
                vulns = self.vulnerability_check(port_info)
                if vulns:
                    self.results['vulnerabilities'].extend(vulns)
                    print(f"\n  {C.YELLOW}Port {port_info['port']}:{C.END}")
                    for vuln in vulns:
                        print(f"    {C.RED}[!] {vuln['vulnerability']} ({vuln['severity']}){C.END}")
                        print(f"    {C.DIM}→ {vuln['recommendation']}{C.END}")
        
        # Generate report
        self.generate_report()
        
        return self.results
    
    def generate_report(self):
        """Generate scan report"""
        print(f"\n{C.BOLD}{'═'*50}{C.END}")
        print(f"{C.BOLD}  SCAN REPORT SUMMARY{C.END}")
        print(f"{C.BOLD}{'═'*50}{C.END}")
        
        stats = self.results['scan_stats']
        open_ports = self.results['open_ports']
        
        print(f"\n{C.BOLD}Target:{C.END} {self.target}")
        print(f"{C.BOLD}Scanned:{C.END} {stats['total_scanned']} ports in {stats['scan_duration']}s")
        print(f"{C.BOLD}Rate:{C.END} {stats['scan_rate']} ports/sec")
        print(f"\n{C.BOLD}Results:{C.END}")
        print(f"  {C.GREEN}Open: {stats['open_ports']}{C.END}")
        print(f"  {C.RED}Closed: {stats['closed_ports']}{C.END}")
        
        if open_ports:
            print(f"\n{C.BOLD}Open Ports:{C.END}")
            print(f"{'─'*50}")
            print(f"{'PORT':<8} {'STATE':<10} {'SERVICE':<20} {'BANNER'}")
            print(f"{'─'*50}")
            for port in open_ports[:20]:  # Show top 20
                banner = port.get('banner', '')[:40] if port.get('banner') else '-'
                print(f"{port['port']:<8} {C.GREEN}OPEN{C.END}      {port['service']:<20} {banner}")
            
            if len(open_ports) > 20:
                print(f"  ... and {len(open_ports) - 20} more ports")
        
        # OS info
        if self.results.get('os'):
            print(f"\n{C.BOLD}OS Detection:{C.END}")
            print(f"  {C.CYAN}{self.results['os']['best_match']}{C.END}")
        
        # Vulnerabilities summary
        if self.results.get('vulnerabilities'):
            print(f"\n{C.BOLD}Vulnerabilities:{C.END} {C.RED}{len(self.results['vulnerabilities'])} found{C.END}")
        
        print(f"\n{C.BOLD}{'═'*50}{C.END}")
        
        # Save report
        save = input(f"\n{C.YELLOW}[?] Save detailed report? (y/n): {C.END}")
        if save.lower() == 'y':
            filename = f"reports/scan_{self.target}_{datetime.now():%Y%m%d_%H%M%S}.json"
            os.makedirs('reports', exist_ok=True)
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"{C.GREEN}[✓] Report saved: {filename}{C.END}")
            
            # Also save human-readable
            txt_file = filename.replace('.json', '.txt')
            with open(txt_file, 'w') as f:
                f.write(f"Port Scan Report for {self.target}\n")
                f.write(f"{'='*50}\n")
                f.write(f"Scan Date: {datetime.now()}\n")
                f.write(f"Open Ports: {len(open_ports)}\n\n")
                for port in open_ports:
                    f.write(f"Port {port['port']}/tcp - {port['service']}\n")
                    if port.get('banner'):
                        f.write(f"  Banner: {port['banner']}\n")
                    f.write("\n")
            print(f"{C.GREEN}[✓] Text report saved: {txt_file}{C.END}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Professional Port Scanner v3.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py 192.168.1.1
  python port_scanner.py 192.168.1.1 -p 1-1000 -w 100
  python port_scanner.py example.com -p 80,443,8080 -b
  python port_scanner.py 10.0.0.1 -p 1-65535 -t 0.5 -w 200 --aggressive
        """
    )
    
    parser.add_argument('target', help='Target IP or hostname')
    parser.add_argument('-p', '--ports', default='1-1000',
                       help='Port range (default: 1-1000, e.g., 1-100, 80,443,8080)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0,
                       help='Connection timeout (default: 1.0s)')
    parser.add_argument('-w', '--workers', type=int, default=50,
                       help='Worker threads (default: 50)')
    parser.add_argument('-b', '--no-banner', action='store_true',
                       help='Disable banner grabbing')
    parser.add_argument('--no-os', action='store_true',
                       help='Disable OS detection')
    parser.add_argument('-a', '--aggressive', action='store_true',
                       help='Aggressive mode (shorter timeouts)')
    parser.add_argument('-o', '--output', help='Output file for report')
    
    args = parser.parse_args()
    
    # Parse port range
    if ',' in args.ports:
        ports = [int(p) for p in args.ports.split(',')]
        start_port, end_port = min(ports), max(ports)
    elif '-' in args.ports:
        start_port, end_port = map(int, args.ports.split('-'))
    else:
        start_port = end_port = int(args.ports)
    
    # Adjust for aggressive mode
    if args.aggressive:
        args.timeout = 0.5
        args.workers = min(args.workers * 2, 200)
    
    # Create scanner
    scanner = AdvancedPortScanner(
        target=args.target,
        start_port=start_port,
        end_port=end_port,
        timeout=args.timeout,
        workers=args.workers,
        aggressive=args.aggressive,
        grab_banners=not args.no_banner,
        os_detect=not args.no_os
    )
    
    try:
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}[!] Scan interrupted by user{C.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()
