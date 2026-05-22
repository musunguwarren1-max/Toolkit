cat > ~/scripts/webscan.py << 'EOF'
#!/usr/bin/env python3
"""Advanced Web Vulnerability Scanner - No dependencies"""
import urllib.request
import urllib.parse
import urllib.error
import ssl
import sys
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

GREEN,RED,YELLOW,CYAN,MAGENTA,BLUE,BOLD,DIM,END='\033[92m','\033[91m','\033[93m','\033[96m','\033[95m','\033[94m','\033[1m','\033[2m','\033[0m'

ssl._create_default_https_context = ssl._create_unverified_context

def make_request(url, timeout=8, method='GET', data=None, headers=None):
    """Make HTTP request with proper error handling"""
    default_headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 12; Mobile) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'close',  # Important: prevent hanging
    }
    
    if headers:
        default_headers.update(headers)
    
    try:
        req = urllib.request.Request(url, data=data, headers=default_headers, method=method)
        response = urllib.request.urlopen(req, timeout=timeout)
        body = response.read().decode('utf-8', errors='ignore')
        resp_headers = dict(response.headers)
        status = response.getcode()
        return status, resp_headers, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode('utf-8', errors='ignore')
        except:
            body = ""
        return e.code, dict(e.headers), body
    except urllib.error.URLError as e:
        return None, {}, f"Connection Error: {str(e.reason)}"
    except socket.timeout:
        return None, {}, "Timeout"
    except Exception as e:
        return None, {}, f"Error: {str(e)}"

class AdvancedWebScanner:
    def __init__(self, url):
        if not url.startswith('http'):
            url = f'http://{url}'
        self.url = url.rstrip('/')
        self.vulns = []
        self.findings = []
        self.info = {}
        
    def gather_info(self):
        """Gather basic information about the target"""
        print(f"\n{CYAN}[1/8] Gathering Target Information...{END}")
        
        status, headers, body = make_request(self.url)
        
        if status:
            print(f"  {GREEN}✓ Status: {status}{END}")
            
            # Server info
            server = headers.get('Server', 'Unknown')
            print(f"  {BLUE}ℹ️  Server: {server}{END}")
            
            # Technology detection
            tech = []
            if 'php' in str(headers).lower() or '.php' in body[:500].lower():
                tech.append('PHP')
            if 'wp-content' in body[:1000].lower():
                tech.append('WordPress')
            if 'joomla' in body[:1000].lower():
                tech.append('Joomla')
            if 'drupal' in body[:1000].lower():
                tech.append('Drupal')
            if 'node' in str(headers).lower():
                tech.append('Node.js')
            if 'nginx' in str(headers).lower():
                tech.append('Nginx')
            if 'apache' in str(headers).lower():
                tech.append('Apache')
            
            if tech:
                print(f"  {MAGENTA}🔧 Detected: {', '.join(tech)}{END}")
                self.info['technologies'] = tech
            
            # Check if it's behind Cloudflare or WAF
            if 'cloudflare' in str(headers).lower():
                print(f"  {YELLOW}🛡️  Behind Cloudflare{END}")
                self.info['waf'] = 'Cloudflare'
            
            # Page title
            title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()
                print(f"  {CYAN}📄 Title: {title[:80]}{END}")
                self.info['title'] = title
        else:
            print(f"  {RED}✗ Could not connect: {body}{END}")
    
    def directory_scan(self):
        """Quick scan for common directories"""
        print(f"\n{CYAN}[2/8] Scanning Common Directories...{END}")
        
        common_dirs = [
            '/admin', '/login', '/wp-admin', '/administrator',
            '/backup', '/backups', '/old', '/test', '/dev',
            '/api', '/v1', '/v2', '/graphql', '/.git',
            '/.env', '/config', '/robots.txt', '/sitemap.xml',
            '/uploads', '/images', '/js', '/css', '/static',
        ]
        
        found_dirs = []
        
        def check_dir(path):
            test_url = urllib.parse.urljoin(self.url, path)
            status, headers, body = make_request(test_url, timeout=3)
            if status and status != 404:
                return path, status
            return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_dir, d): d for d in common_dirs}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    path, status = result
                    found_dirs.append((path, status))
                    print(f"  {YELLOW}• Found: {path} (Status: {status}){END}")
        
        if not found_dirs:
            print(f"  {GREEN}✓ No common directories found{END}")
        
        self.findings.extend([('Directory', f"{d[0]} ({d[1]})") for d in found_dirs])
        return found_dirs
    
    def test_sqli(self):
        """Test SQL injection with better payloads"""
        print(f"\n{CYAN}[3/8] Testing SQL Injection...{END}")
        
        error_patterns = [
            'sql syntax', 'mysql error', 'mysql_fetch', 'sqlite3',
            'unclosed quotation', 'odbc driver', 'microsoft ole db',
            'postgresql', 'warning.*mysql', 'valid mysql',
            'ora-[0-9]{5}', 'sql server.*error'
        ]
        
        payloads = [
            "'", 
            "\"", 
            "1' OR '1'='1",
            "1' OR '1'='1' --",
            "1' OR '1'='1' #",
            "' UNION SELECT NULL--",
            "1 AND 1=1",
            "1 AND 1=2",
            "1; SELECT pg_sleep(2)--",
        ]
        
        # Test URL parameters and paths
        found = False
        
        for payload in payloads:
            try:
                # Method 1: Query parameter injection
                test_url = f"{self.url}?id={urllib.parse.quote(payload)}"
                status, headers, body = make_request(test_url, timeout=5)
                
                if body:
                    for pattern in error_patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            self.vulns.append(('SQL Injection', test_url, 'CRITICAL'))
                            print(f"  {RED}⚠️  SQLi FOUND (error-based): {test_url}{END}")
                            print(f"  {DIM}Pattern: {pattern}{END}")
                            found = True
                            break
                
                if found: break
                
                # Method 2: Path injection
                test_url2 = f"{self.url}/{urllib.parse.quote(payload)}"
                status2, headers2, body2 = make_request(test_url2, timeout=5)
                
                if body2:
                    for pattern in error_patterns:
                        if re.search(pattern, body2, re.IGNORECASE):
                            self.vulns.append(('SQL Injection', test_url2, 'CRITICAL'))
                            print(f"  {RED}⚠️  SQLi FOUND (path-based): {test_url2}{END}")
                            found = True
                            break
                
            except: pass
        
        if not found:
            print(f"  {GREEN}✓ No SQLi detected{END}")
    
    def test_xss(self):
        """Test XSS with various contexts"""
        print(f"\n{CYAN}[4/8] Testing XSS...{END}")
        
        payloads = [
            ("<script>alert('XSS')</script>", "HTML context"),
            ('"><script>alert(1)</script>', "Attribute breakout"),
            ("<img src=x onerror=alert(1)>", "Image tag injection"),
            ("<svg onload=alert(1)>", "SVG injection"),
            ("'-alert(1)-'", "JavaScript context"),
            ("</script><script>alert(1)</script>", "Script breakout"),
        ]
        
        found = False
        
        for payload, context in payloads:
            try:
                # Test in query parameter
                test_url = f"{self.url}?q={urllib.parse.quote(payload)}"
                status, headers, body = make_request(test_url, timeout=5)
                
                if body and payload in body:
                    self.vulns.append(('XSS (Reflected)', test_url, 'HIGH'))
                    print(f"  {RED}⚠️  XSS FOUND ({context}): {test_url}{END}")
                    found = True
                    break
                
                # Test in path
                test_url2 = f"{self.url}/{urllib.parse.quote(payload)}"
                status2, headers2, body2 = make_request(test_url2, timeout=5)
                
                if body2 and payload in body2:
                    self.vulns.append(('XSS (Path-based)', test_url2, 'HIGH'))
                    print(f"  {RED}⚠️  XSS FOUND in path: {test_url2}{END}")
                    found = True
                    break
                    
            except: pass
        
        if not found:
            print(f"  {GREEN}✓ No reflected XSS detected{END}")
    
    def test_security_headers(self):
        """Check security headers comprehensively"""
        print(f"\n{CYAN}[5/8] Analyzing Security Headers...{END}")
        
        try:
            status, headers, body = make_request(self.url)
            
            if not status:
                print(f"  {YELLOW}⚠️  Could not fetch headers{END}")
                return
            
            security_checks = {
                'Strict-Transport-Security': {
                    'description': 'HTTPS enforcement (HSTS)',
                    'severity': 'MEDIUM',
                    'recommendation': 'Add HSTS header to enforce HTTPS'
                },
                'Content-Security-Policy': {
                    'description': 'Prevents XSS attacks',
                    'severity': 'HIGH',
                    'recommendation': 'Implement CSP to control resource loading'
                },
                'X-Frame-Options': {
                    'description': 'Prevents clickjacking',
                    'severity': 'MEDIUM',
                    'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
                },
                'X-Content-Type-Options': {
                    'description': 'Prevents MIME sniffing',
                    'severity': 'LOW',
                    'recommendation': 'Add X-Content-Type-Options: nosniff'
                },
                'Referrer-Policy': {
                    'description': 'Controls referrer information',
                    'severity': 'LOW',
                    'recommendation': 'Set appropriate Referrer-Policy'
                },
                'Permissions-Policy': {
                    'description': 'Restricts browser features',
                    'severity': 'LOW',
                    'recommendation': 'Implement Permissions-Policy header'
                },
            }
            
            missing_count = 0
            for header, info in security_checks.items():
                if header not in headers:
                    missing_count += 1
                    self.findings.append(('Missing Header', f"{header}: {info['description']}"))
                    print(f"  {YELLOW}⚠️  Missing: {header} - {info['description']}{END}")
                else:
                    print(f"  {GREEN}✓ {header}: {headers[header][:60]}{END}")
            
            if missing_count == 0:
                print(f"  {GREEN}✅ All security headers present!{END}")
            else:
                print(f"  {YELLOW}📊 Missing {missing_count}/{len(security_checks)} security headers{END}")
                
        except Exception as e:
            print(f"  {RED}✗ Error: {str(e)[:100]}{END}")
    
    def test_sensitive_files(self):
        """Check for exposed sensitive files"""
        print(f"\n{CYAN}[6/8] Checking Sensitive Files...{END}")
        
        sensitive_files = {
            '/.git/HEAD': 'Git repository exposed',
            '/.env': 'Environment variables exposed',
            '/.env.backup': 'Environment backup',
            '/wp-config.php': 'WordPress config (should be blocked)',
            '/config.php': 'Configuration file',
            '/backup.sql': 'Database backup',
            '/dump.sql': 'Database dump',
            '/phpinfo.php': 'PHP info disclosure',
            '/server-status': 'Apache server status',
            '/.DS_Store': 'macOS file (path disclosure)',
        }
        
        found_files = []
        
        def check_file(path, desc):
            test_url = urllib.parse.urljoin(self.url, path)
            status, headers, body = make_request(test_url, timeout=4)
            if status == 200:
                return path, desc, body[:200]
            return None
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(check_file, p, d): p for p, d in sensitive_files.items()}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    path, desc, content = result
                    found_files.append((path, desc))
                    
                    if path == '/.git/HEAD' and 'ref:' in content:
                        self.vulns.append(('Git Exposed', path, 'CRITICAL'))
                        print(f"  {RED}⚠️  CRITICAL: {desc} at {path}{END}")
                    elif path == '/.env' and ('DB_' in content or 'API_' in content):
                        self.vulns.append(('Env File Exposed', path, 'CRITICAL'))
                        print(f"  {RED}⚠️  CRITICAL: {desc} at {path}{END}")
                    else:
                        self.findings.append(('Sensitive File', f"{path} - {desc}"))
                        print(f"  {YELLOW}• {desc}: {path}{END}")
        
        if not found_files:
            print(f"  {GREEN}✓ No sensitive files exposed{END}")
    
    def test_cors(self):
        """Check CORS configuration"""
        print(f"\n{CYAN}[7/8] Testing CORS Configuration...{END}")
        
        try:
            status, headers, body = make_request(self.url, headers={
                'Origin': 'https://evil.com'
            })
            
            cors_header = headers.get('Access-Control-Allow-Origin', '')
            cors_creds = headers.get('Access-Control-Allow-Credentials', '')
            
            if cors_header == '*' and cors_creds == 'true':
                self.vulns.append(('CORS Misconfiguration', self.url, 'HIGH'))
                print(f"  {RED}⚠️  CORS allows any origin with credentials!{END}")
            elif cors_header == '*':
                self.findings.append(('CORS', 'Allows any origin (without credentials)'))
                print(f"  {YELLOW}• CORS allows any origin{END}")
            elif cors_header == 'https://evil.com':
                self.vulns.append(('CORS Misconfiguration', self.url, 'HIGH'))
                print(f"  {RED}⚠️  CORS reflects origin header!{END}")
            else:
                print(f"  {GREEN}✓ CORS appears properly configured{END}")
                
        except Exception as e:
            print(f"  {YELLOW}⚠️  Could not test CORS: {str(e)[:80]}{END}")
    
    def test_http_methods(self):
        """Test allowed HTTP methods"""
        print(f"\n{CYAN}[8/8] Testing HTTP Methods...{END}")
        
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS', 'CONNECT']
        
        for method in dangerous_methods:
            try:
                status, headers, body = make_request(self.url, method=method, timeout=3)
                if status not in [405, 501, None]:
                    if method in ['PUT', 'DELETE']:
                        self.vulns.append(('Dangerous Method', f"{method} allowed", 'MEDIUM'))
                        print(f"  {RED}⚠️  {method} method allowed (Status: {status}){END}")
                    else:
                        self.findings.append(('HTTP Method', f"{method} allowed"))
                        print(f"  {YELLOW}• {method} method allowed{END}")
            except:
                pass
        
        print(f"  {GREEN}✓ HTTP methods check complete{END}")
    
    def run_full_scan(self):
        """Run comprehensive scan"""
        print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════╗{END}")
        print(f"{BOLD}{CYAN}║   🌐 ADVANCED WEB SCANNER v2.0  🌐  ║{END}")
        print(f"{BOLD}{CYAN}║      Full Security Assessment         ║{END}")
        print(f"{BOLD}{CYAN}╚══════════════════════════════════════╝{END}")
        print(f"\n{CYAN}🎯 Target: {self.url}{END}")
        print(f"{CYAN}⏰ Started: {__import__('datetime').datetime.now().strftime('%H:%M:%S')}{END}")
        
        try:
            # Information gathering
            self.gather_info()
            
            # Discovery
            self.directory_scan()
            self.test_sensitive_files()
            
            # Injection tests
            self.test_sqli()
            self.test_xss()
            
            # Configuration tests
            self.test_security_headers()
            self.test_cors()
            self.test_http_methods()
            
        except KeyboardInterrupt:
            print(f"\n\n{YELLOW}⚠️  Scan interrupted by user{END}")
        except Exception as e:
            print(f"\n{RED}✗ Unexpected error: {e}{END}")
        
        # Generate report
        self.print_report()
    
    def print_report(self):
        """Print comprehensive report"""
        print(f"\n\n{BOLD}{'='*45}{END}")
        print(f"{BOLD}📊 SECURITY ASSESSMENT REPORT{END}")
        print(f"{BOLD}{'='*45}{END}")
        print(f"\n{BOLD}Target:{END} {self.url}")
        print(f"{BOLD}Scan Time:{END} {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Risk score
        risk_score = 0
        for vuln in self.vulns:
            if vuln[2] == 'CRITICAL': risk_score += 25
            elif vuln[2] == 'HIGH': risk_score += 15
            elif vuln[2] == 'MEDIUM': risk_score += 10
            elif vuln[2] == 'LOW': risk_score += 5
        
        if risk_score >= 50:
            risk_level = f"{RED}CRITICAL RISK{END}"
        elif risk_score >= 30:
            risk_level = f"{YELLOW}HIGH RISK{END}"
        elif risk_score >= 15:
            risk_level = f"{YELLOW}MEDIUM RISK{END}"
        elif risk_score > 0:
            risk_level = f"{CYAN}LOW RISK{END}"
        else:
            risk_level = f"{GREEN}NO CRITICAL ISSUES{END}"
        
        print(f"{BOLD}Risk Level:{END} {risk_level} (Score: {risk_score})")
        
        # Vulnerabilities
        if self.vulns:
            print(f"\n{BOLD}{RED}⚠️  VULNERABILITIES ({len(self.vulns)}):{END}")
            for vtype, detail, severity in self.vulns:
                color = RED if severity in ['CRITICAL','HIGH'] else YELLOW
                print(f"\n  {color}[{severity}] {vtype}{END}")
                print(f"  {DIM}└─ {detail}{END}")
        
        # Findings
        if self.findings:
            print(f"\n{BOLD}{YELLOW}📝 FINDINGS ({len(self.findings)}):{END}")
            for ftype, detail in self.findings[:10]:
                print(f"  {YELLOW}• {ftype}:{END} {DIM}{detail}{END}")
        
        # Target info
        if self.info:
            print(f"\n{BOLD}{BLUE}ℹ️  TARGET INFO:{END}")
            for key, value in self.info.items():
                print(f"  {BLUE}• {key}:{END} {value}")
        
        # Summary
        print(f"\n{BOLD}{'='*45}{END}")
        if not self.vulns:
            print(f"{GREEN}✅ No critical vulnerabilities found!{END}")
        else:
            print(f"{RED}⚠️  Action required - {len(self.vulns)} vulnerabilities need attention{END}")
        
        print(f"\n{CYAN}💡 Recommendations:{END}")
        print(f"  • Always keep software updated")
        print(f"  • Implement all security headers")
        print(f"  • Use HTTPS everywhere")
        print(f"  • Regular security assessments")
        print(f"  • Backup sensitive files securely")
        
        print(f"\n{YELLOW}⚠️  DISCLAIMER: Only test sites you own or have permission!{END}")
        print(f"{BOLD}{'='*45}{END}\n")

def main():
    if len(sys.argv) < 2:
        print(f"""
{BOLD}{CYAN}🌐 Advanced Web Security Scanner v2.0{END}

{YELLOW}Usage:{END}
  webscan <url>
  webscan http://example.com
  webscan https://target.com/page

{YELLOW}Features:{END}
  • Technology detection
  • Directory discovery
  • SQL Injection testing
  • XSS detection
  • Security headers analysis
  • CORS testing
  • HTTP methods check
  • Sensitive file detection

{YELLOW}Examples:{END}
  webscan http://testphp.vulnweb.com
  webscan http://192.168.0.1
  webscan https://example.com

{YELLOW}⚠️  Warning:{END}
  Only scan sites you own or have explicit permission to test!
        """)
        sys.exit(1)
    
    url = sys.argv[1]
    scanner = AdvancedWebScanner(url)
    scanner.run_full_scan()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}⚠️  Scan stopped{END}")
    except Exception as e:
        print(f"\n{RED}✗ Fatal error: {e}{END}")
EOF

chmod +x ~/scripts/webscan.py
