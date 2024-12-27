import os
import aiohttp
import asyncio
import logging
import json
import socket
import ssl
import dns.resolver
import nmap
import whois
import re
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='security_scanner.log'
)

logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

class SecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.vulnerabilities = []
        self.exploits = []
        self.risk_level = "Low"
        self.ports_scanned = []
        self.server_info = {}
        self.whois_data = {}
        self.dns_records = []
        self.ssl_info = {}
        
    async def full_scan(self):
        """Execute comprehensive security scan"""
        try:
            scan_start_time = datetime.now()
            
            async with aiohttp.ClientSession() as session:
                # Run all scans concurrently
                await asyncio.gather(
                    self.port_scan(),
                    self.ssl_scan(),
                    self.get_server_info(session),
                    self.get_dns_info(),
                    self.get_whois_info(),
                    self.analyze_webpage_content(session),
                    self.vulnerability_scan(session),
                    self.check_exploit_db(session)
                )
            
            self.calculate_risk_level()
            scan_duration = (datetime.now() - scan_start_time).total_seconds()
            report_path = await self.generate_report()
            
            return {
                'vulnerabilities': self.vulnerabilities,
                'exploits': self.exploits,
                'risk_level': self.risk_level,
                'scan_duration': scan_duration,
                'report_path': report_path,
                'server_info': self.server_info,
                'whois_data': self.whois_data,
                'dns_records': self.dns_records,
                'ssl_info': self.ssl_info,
                'ports_scanned': self.ports_scanned,
                'webpage_info': self.webpage_info  # Add webpage analysis results
            }
            
        except Exception as e:
            logger.error(f"Error in full scan: {str(e)}")
            raise

    async def get_server_info(self, session):
        """Get detailed server information"""
        try:
            async with session.get(self.target_url) as response:
                self.server_info = {
                    'ip_address': socket.gethostbyname(self.domain),
                    'server': response.headers.get('Server', 'Unknown'),
                    'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                    'content_type': response.headers.get('Content-Type', 'Unknown'),
                    'headers': dict(response.headers),
                    'response_time': response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0
                }
        except Exception as e:
            logger.error(f"Error getting server info: {str(e)}")
            self.server_info = {'error': str(e)}

    async def get_dns_info(self):
        """Get DNS records"""
        try:
            resolver = dns.resolver.Resolver()
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(self.domain, record_type)
                    self.dns_records.append({
                        'type': record_type,
                        'records': [str(answer) for answer in answers]
                    })
                except dns.resolver.NoAnswer:
                    continue
                except Exception as e:
                    logger.error(f"Error resolving {record_type} record: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error getting DNS info: {str(e)}")

    async def get_whois_info(self):
        """Get WHOIS information"""
        try:
            whois_data = whois.whois(self.domain)
            self.whois_data = {
                'registrar': whois_data.registrar,
                'creation_date': whois_data.creation_date,
                'expiration_date': whois_data.expiration_date,
                'last_updated': whois_data.updated_date,
                'name_servers': whois_data.name_servers,
                'status': whois_data.status,
                'emails': whois_data.emails,
                'org': whois_data.org
            }
        except Exception as e:
            logger.error(f"Error getting WHOIS info: {str(e)}")
            self.whois_data = {'error': str(e)}


    async def vulnerability_scan(self, session):
        """Comprehensive vulnerability scan combining multiple checks"""
        try:
            # Create a list of coroutines to run concurrently
            scan_tasks = [
                self._check_security_headers(session),  # Changed to use the async version
                self.check_sensitive_files(session),
                self.check_xss(session),
                self.check_sql_injection(session),
                self.check_csrf(session),
                self.check_file_inclusion(session)
            ]
            
            # Run all vulnerability checks concurrently using gather
            await asyncio.gather(*scan_tasks)
                
        except Exception as e:
            logger.error(f"Error in vulnerability scan: {str(e)}")
            self.vulnerabilities.append({
                'type': 'Scan Error',
                'severity': 'Low',
                'description': f'Error during vulnerability scan: {str(e)}',
                'remediation': 'Ensure all security checks are properly configured.'
            })


    async def _check_security_headers(self, session):
        """Check for missing or misconfigured security headers"""
        try:
            async with session.get(self.target_url) as response:
                headers = response.headers
                security_headers = {
                    'Strict-Transport-Security': 'Missing HSTS header',
                    'X-Frame-Options': 'Missing X-Frame-Options header',
                    'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                    'Content-Security-Policy': 'Missing Content Security Policy',
                    'X-XSS-Protection': 'Missing XSS Protection header',
                    'Referrer-Policy': 'Missing Referrer Policy',
                    'Permissions-Policy': 'Missing Permissions Policy',
                    'Cross-Origin-Embedder-Policy': 'Missing COEP header',
                    'Cross-Origin-Opener-Policy': 'Missing COOP header',
                    'Cross-Origin-Resource-Policy': 'Missing CORP header'
                }
                
                for header, message in security_headers.items():
                    if header not in headers:
                        self.vulnerabilities.append({
                            'type': 'Security Headers',
                            'severity': 'Medium',
                            'description': message,
                            'remediation': f'Add {header} header with appropriate values'
                        })
                        
                # Add header analysis to server_info
                self.server_info['security_headers'] = {
                    header: headers.get(header, 'Not Present')
                    for header in security_headers.keys()
                }
                        
        except Exception as e:
            logger.error(f"Error checking security headers: {str(e)}")


    async def analyze_webpage_content(self, session):
        """Analyze webpage content for security and SEO relevant information"""
        try:
            async with session.get(self.target_url) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                # Initialize webpage info dictionary
                self.webpage_info = {
                    'meta_tags': {},
                    'links': {
                        'internal': [],
                        'external': [],
                        'social': []
                    },
                    'scripts': {
                        'inline': 0,
                        'external': []
                    },
                    'images': {
                        'count': 0,
                        'missing_alt': 0
                    },
                    'forms': [],
                    'technologies': set(),
                    'response_headers': dict(response.headers),
                    'content_size': len(content),
                    'load_time': response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0
                }
                
                # Analyze meta tags
                for meta in soup.find_all('meta'):
                    name = meta.get('name', meta.get('property', ''))
                    content = meta.get('content', '')
                    if name and content:
                        self.webpage_info['meta_tags'][name] = content
                
                # Analyze links
                base_domain = urlparse(self.target_url).netloc
                social_domains = {'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com'}
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    parsed_href = urlparse(urljoin(self.target_url, href))
                    if parsed_href.netloc == base_domain:
                        self.webpage_info['links']['internal'].append(href)
                    elif any(social in parsed_href.netloc for social in social_domains):
                        self.webpage_info['links']['social'].append(href)
                    else:
                        self.webpage_info['links']['external'].append(href)
                
                # Analyze scripts
                for script in soup.find_all('script'):
                    if script.get('src'):
                        self.webpage_info['scripts']['external'].append(script['src'])
                    else:
                        self.webpage_info['scripts']['inline'] += 1
                
                # Analyze images
                images = soup.find_all('img')
                self.webpage_info['images']['count'] = len(images)
                self.webpage_info['images']['missing_alt'] = len([img for img in images if not img.get('alt')])
                
                # Analyze forms
                for form in soup.find_all('form'):
                    form_info = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'get'),
                        'inputs': [{'type': input.get('type', ''), 'name': input.get('name', '')}
                                for input in form.find_all('input')]
                    }
                    self.webpage_info['forms'].append(form_info)
                
                # Detect technologies
                if soup.find(class_='wp-'):
                    self.webpage_info['technologies'].add('WordPress')
                if 'jquery' in str(soup).lower():
                    self.webpage_info['technologies'].add('jQuery')
                if 'bootstrap' in str(soup).lower():
                    self.webpage_info['technologies'].add('Bootstrap')
                if 'react' in str(soup).lower():
                    self.webpage_info['technologies'].add('React')
                
                # Convert set to list for JSON serialization
                self.webpage_info['technologies'] = list(self.webpage_info['technologies'])
                
                # Add security checks based on content analysis
                self._check_content_security(soup)
                
        except Exception as e:
            logger.error(f"Error analyzing webpage content: {str(e)}")
            self.webpage_info = {'error': str(e)}

    def _check_content_security(self, soup):
        """Check for security issues in webpage content"""
        # Check for potentially dangerous inline scripts
        inline_scripts = soup.find_all('script', src=None)
        for script in inline_scripts:
            script_content = script.string or ''
            if 'eval(' in script_content or 'document.write(' in script_content:
                self.vulnerabilities.append({
                    'type': 'Unsafe JavaScript',
                    'severity': 'Medium',
                    'description': 'Potentially dangerous inline JavaScript detected',
                    'remediation': 'Avoid using eval() or document.write(). Use safer alternatives.'
                })
        
        # Check for password fields in non-HTTPS forms
        if not self.target_url.startswith('https://'):
            password_fields = soup.find_all('input', {'type': 'password'})
            if password_fields:
                self.vulnerabilities.append({
                    'type': 'Insecure Password Field',
                    'severity': 'High',
                    'description': 'Password field detected on non-HTTPS page',
                    'remediation': 'Ensure all pages with password fields use HTTPS'
                })
            

    async def port_scan(self):
        """Perform port scanning using nmap"""
        try:
            nm = nmap.PortScanner()
            nm.scan(self.domain, arguments='-sS -sV -p1-1000 --open')
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        self.ports_scanned.append({
                            'port': port,
                            'state': service['state'],
                            'service': service['name'],
                            'version': service['version']
                        })
                        
                        # Check for potentially vulnerable services
                        if service['version']:
                            self.check_service_vulnerabilities(service['name'], service['version'])
                            
        except Exception as e:
            logger.error(f"Error in port scan: {str(e)}")
            self.vulnerabilities.append({
                'type': 'Port Scan Error',
                'severity': 'Low',
                'description': f'Unable to complete port scan: {str(e)}',
                'remediation': 'Ensure the target is accessible and nmap is properly configured.'
            })

    def check_service_vulnerabilities(self, service_name, version):
        """Check known vulnerabilities for detected services"""
        common_vulnerable_versions = {
            'apache': ['2.4.49', '2.4.50'],
            'nginx': ['1.16.1', '1.17.0'],
            'openssh': ['7.2p1', '7.2p2'],
            'mysql': ['5.5.60', '5.6.40', '5.7.24']
        }
        
        service_name = service_name.lower()
        if service_name in common_vulnerable_versions:
            if version in common_vulnerable_versions[service_name]:
                self.vulnerabilities.append({
                    'type': 'Vulnerable Service',
                    'severity': 'High',
                    'description': f'Detected {service_name} version {version} with known vulnerabilities',
                    'remediation': f'Upgrade {service_name} to the latest stable version',
                    'software_version': version
                })

    async def ssl_scan(self):
        """Perform SSL/TLS security scan"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        self.vulnerabilities.append({
                            'type': 'SSL Certificate',
                            'severity': 'Critical',
                            'description': 'SSL certificate has expired',
                            'remediation': 'Renew SSL certificate immediately'
                        })
                    
                    # Check weak cipher suites
                    cipher = ssock.cipher()
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
                    if any(weak in cipher[0] for weak in weak_ciphers):
                        self.vulnerabilities.append({
                            'type': 'Weak Cipher',
                            'severity': 'High',
                            'description': f'Weak cipher detected: {cipher[0]}',
                            'remediation': 'Configure server to use strong cipher suites only'
                        })
                    
        except ssl.SSLError as e:
            logger.error(f"SSL Error: {str(e)}")
            self.vulnerabilities.append({
                'type': 'SSL Configuration',
                'severity': 'High',
                'description': f'SSL configuration error: {str(e)}',
                'remediation': 'Review and fix SSL configuration'
            })
        except Exception as e:
            logger.error(f"Error in SSL scan: {str(e)}")

    def check_security_headers(self, headers):
        """Check for missing or misconfigured security headers"""
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'Content-Security-Policy': 'Missing Content Security Policy',
            'X-XSS-Protection': 'Missing XSS Protection header'
        }
        
        for header, message in security_headers.items():
            if header not in headers:
                self.vulnerabilities.append({
                    'type': 'Security Headers',
                    'severity': 'Medium',
                    'description': message,
                    'remediation': f'Add {header} header with appropriate values'
                })

    async def check_sensitive_files(self, session):
        """Check for exposed sensitive files and directories"""
        sensitive_files = [
            '/.git/config',
            '/.env',
            '/wp-config.php',
            '/phpinfo.php',
            '/administrator/manifests/files/joomla.xml'
        ]
        
        for file_path in sensitive_files:
            try:
                url = urljoin(self.target_url, file_path)
                async with session.get(url) as response:
                    if response.status == 200:
                        self.vulnerabilities.append({
                            'type': 'Sensitive File Exposure',
                            'severity': 'High',
                            'description': f'Sensitive file detected: {file_path}',
                            'remediation': f'Remove or protect access to {file_path}'
                        })
            except Exception as e:
                logger.error(f"Error checking sensitive file {file_path}: {str(e)}")

    async def check_sql_injection(self, session):
        """Check for SQL injection vulnerabilities"""
        test_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1 UNION SELECT null,null,null--"
        ]
        
        try:
            forms = await self.get_forms(session)
            
            for form in forms:
                for payload in test_payloads:
                    try:
                        data = {field: payload for field in form['fields']}
                        async with session.post(form['action'], data=data) as response:
                            content = await response.text()
                            if self.check_sql_error_patterns(content):
                                self.vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'severity': 'Critical',
                                    'description': f'Potential SQL injection vulnerability in form: {form["action"]}',
                                    'remediation': 'Implement proper input validation and parameterized queries'
                                })
                                break
                    except Exception as e:
                        logger.error(f"Error in SQL injection check for form {form['action']}: {str(e)}")
        except Exception as e:
            logger.error(f"Error in SQL injection check: {str(e)}")

    def check_sql_error_patterns(self, content):
        """Check for SQL error messages in response"""
        sql_errors = [
            'mysql_fetch_array',
            'ORA-[0-9][0-9][0-9][0-9]',
            'Microsoft SQL Native Client error',
            'SQLSTATE[',
            'ODBC SQL Server Driver'
        ]
        
        return any(re.search(error, content, re.IGNORECASE) for error in sql_errors)

    async def check_xss(self, session):
        """Check for Cross-Site Scripting (XSS) vulnerabilities"""
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>'
        ]
        
        try:
            forms = await self.get_forms(session)
            
            for form in forms:
                for payload in xss_payloads:
                    try:
                        data = {field: payload for field in form['fields']}
                        async with session.post(form['action'], data=data) as response:
                            content = await response.text()
                            if payload in content:
                                self.vulnerabilities.append({
                                    'type': 'Cross-Site Scripting (XSS)',
                                    'severity': 'High',
                                    'description': f'Potential XSS vulnerability in form: {form["action"]}',
                                    'remediation': 'Implement proper input validation and output encoding'
                                })
                                break
                    except Exception as e:
                        logger.error(f"Error in XSS check for form {form['action']}: {str(e)}")
        except Exception as e:
            logger.error(f"Error in XSS check: {str(e)}")

    async def check_csrf(self, session):
        """Check for CSRF vulnerabilities"""
        try:
            forms = await self.get_forms(session)
            
            for form in forms:
                csrf_tokens = [
                    'csrf_token',
                    '_token',
                    'authenticity_token',
                    'CSRFToken'
                ]
                
                if not any(token in form['fields'] for token in csrf_tokens):
                    self.vulnerabilities.append({
                        'type': 'CSRF',
                        'severity': 'Medium',
                        'description': f'No CSRF token found in form: {form["action"]}',
                        'remediation': 'Implement CSRF tokens for all forms'
                    })
        except Exception as e:
            logger.error(f"Error in CSRF check: {str(e)}")

    async def check_file_inclusion(self, session):
        """Check for File Inclusion vulnerabilities"""
        lfi_payloads = [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '/etc/passwd%00',
            'file:///etc/passwd'
        ]
        
        for payload in lfi_payloads:
            try:
                url = f"{self.target_url}?file={payload}"
                async with session.get(url) as response:
                    content = await response.text()
                    if 'root:x:0:0:' in content:
                        self.vulnerabilities.append({
                            'type': 'File Inclusion',
                            'severity': 'Critical',
                            'description': 'Local File Inclusion vulnerability detected',
                            'remediation': 'Implement proper input validation and restrict file access'
                        })
                        break
            except Exception as e:
                logger.error(f"Error in file inclusion check: {str(e)}")

    async def get_forms(self, session):
        """Extract forms from the webpage with better error handling"""
        try:
            content, status = await self.make_request(session, self.target_url)
            if not content:
                return []
                
            soup = BeautifulSoup(content, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(self.target_url, form.get('action', '')),
                    'method': form.get('method', 'get').lower(),
                    'fields': []
                }
                
                # Get all input fields including hidden fields
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    field_name = input_field.get('name')
                    if field_name:
                        form_data['fields'].append(field_name)
                        
                forms.append(form_data)
            
            return forms
        except Exception as e:
            logger.error(f"Error extracting forms: {str(e)}")
            return []

    def calculate_risk_level(self):
        """Calculate overall risk level based on vulnerabilities"""
        severity_scores = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1
        }
        
        total_score = sum(severity_scores.get(v['severity'], 0) for v in self.vulnerabilities)
        
        if total_score == 0:
            self.risk_level = "Low"
        elif total_score <= 3:
            self.risk_level = "Medium"
        elif total_score <= 6:
            self.risk_level = "High"
        else:
            self.risk_level = "Critical"

    async def check_vulnerabilities(self, session):
        """Additional vulnerability checks"""
        try:
            # Check for directory listing
            async with session.get(f"{self.target_url}/images/") as response:
                content = await response.text()
                if 'Index of /images' in content:
                    self.vulnerabilities.append({
                        'type': 'Directory Listing',
                        'severity': 'Medium',
                        'description': 'Directory listing is enabled',
                        'remediation': 'Disable directory listing in server configuration'
                    })

                    # Check for server version disclosure
            async with session.get(self.target_url) as response:
                server_header = response.headers.get('Server', '')
                if server_header and not server_header == 'Server':
                    self.vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'Low',
                        'description': f'Server version disclosed: {server_header}',
                        'remediation': 'Configure server to hide version information'
                    })
            
                # Check for backup files
                backup_extensions = ['.bak', '.backup', '.old', '.tmp', '~']
                test_files = ['index', 'config', 'admin']
                
                for file in test_files:
                    for ext in backup_extensions:
                        test_url = f"{self.target_url}/{file}{ext}"
                        try:
                            async with session.get(test_url) as response:
                                if response.status == 200:
                                    self.vulnerabilities.append({
                                        'type': 'Backup Files',
                                        'severity': 'Medium',
                                        'description': f'Potential backup file found: {test_url}',
                                        'remediation': 'Remove backup files from public access'
                                    })
                        except Exception as e:
                            logger.error(f"Error checking backup file {test_url}: {str(e)}")
            
                 # Check for debug endpoints
                debug_paths = ['/debug', '/console', '/phpinfo.php', '/server-status']
                for path in debug_paths:
                    try:
                        async with session.get(f"{self.target_url}{path}") as response:
                            if response.status == 200:
                                self.vulnerabilities.append({
                                    'type': 'Debug Endpoint',
                                    'severity': 'High',
                                    'description': f'Debug endpoint accessible: {path}',
                                    'remediation': 'Disable or protect debug endpoints in production'
                                })
                    except Exception as e:
                        logger.error(f"Error checking debug endpoint {path}: {str(e)}")

                # Check for mixed content
                try:
                    async with session.get(self.target_url) as response:
                        content = await response.text()
                        soup = BeautifulSoup(content, 'html.parser')
                        
                        # Check for HTTP resources on HTTPS page
                        if self.target_url.startswith('https://'):
                            mixed_content = []
                            for tag in soup.find_all(['script', 'link', 'img']):
                                src = tag.get('src') or tag.get('href')
                                if src and src.startswith('http://'):
                                    mixed_content.append(src)
                            
                            if mixed_content:
                                self.vulnerabilities.append({
                                    'type': 'Mixed Content',
                                    'severity': 'Medium',
                                    'description': 'Mixed content detected (HTTP resources on HTTPS page)',
                                    'remediation': 'Update all resources to use HTTPS'
                                })

                except Exception as e:
                    logger.error(f"Error checking for mixed content: {str(e)}")

        except Exception as e:
            logger.error(f"Error checking directory listing: {str(e)}")

    async def check_exploit_db(self, session):
        """Query local Exploit-DB clone for known exploits"""
        try:
            # Assuming the Exploit-DB repository is cloned in the same directory
            exploits_path = os.path.join(os.path.dirname(__file__), 'exploit-database', 'exploits')
            
            for vuln in self.vulnerabilities:
                found_exploits = []
                search_terms = [
                    vuln['type'].lower(),
                    vuln.get('software_version', '').lower(),
                    self.server_info.get('server', '').lower()
                ]
                
                # Walk through the exploits directory
                for root, _, files in os.walk(exploits_path):
                    for file in files:
                        if file.endswith('.rb') or file.endswith('.py') or file.endswith('.txt'):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read().lower()
                                    # Check if any search terms match in the exploit content
                                    if any(term in content for term in search_terms if term):
                                        exploit_info = self._parse_exploit_file(file_path, content)
                                        if exploit_info:
                                            found_exploits.append(exploit_info)
                            except Exception as e:
                                logger.error(f"Error reading exploit file {file_path}: {str(e)}")
                
                # Add found exploits to the vulnerability
                if found_exploits:
                    vuln['exploits'] = found_exploits
                    # Update risk level if exploits are found
                    if vuln['severity'] != 'Critical':
                        vuln['severity'] = 'High'
                    
        except Exception as e:
            logger.error(f"Error checking local Exploit-DB: {str(e)}")

    def _parse_exploit_file(self, file_path, content):
        """Parse exploit file for relevant information"""
        try:
            # Extract metadata from exploit file
            title = ""
            author = ""
            date = ""
            description = ""
            
            # Common patterns in exploit files
            patterns = {
                'title': [r'# Title: (.+)', r'Title: (.+)', r'Name: (.+)'],
                'author': [r'# Author: (.+)', r'Author: (.+)'],
                'date': [r'# Date: (.+)', r'Date: (.+)'],
                'description': [r'# Description: (.+)', r'Description: (.+)']
            }
            
            for field, field_patterns in patterns.items():
                for pattern in field_patterns:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        locals()[field] = match.group(1).strip()
                        break
            
            # Extract exploitation steps or proof of concept if available
            exploitation_steps = self._extract_exploitation_steps(content)
            
            return {
                'file_path': os.path.basename(file_path),
                'title': title or os.path.basename(file_path),
                'author': author,
                'date': date,
                'description': description,
                'exploitation_steps': exploitation_steps
            }
        except Exception as e:
            logger.error(f"Error parsing exploit file: {str(e)}")
            return None

    def _extract_exploitation_steps(self, content):
        """Extract exploitation steps or proof of concept from exploit content"""
        try:
            # Common section markers in exploit files
            section_markers = [
                (r'# PoC:|# Proof of Concept:', r'#'),
                (r'Steps to reproduce:', r'\n\n'),
                (r'Usage:', r'\n\n'),
                (r'Example:|Examples:', r'\n\n')
            ]
            
            for start_marker, end_marker in section_markers:
                match = re.search(f'{start_marker}(.*?){end_marker}', content, re.DOTALL | re.IGNORECASE)
                if match:
                    steps = match.group(1).strip()
                    # Clean up the steps
                    steps = re.sub(r'#.*?\n', '\n', steps)  # Remove comment lines
                    steps = re.sub(r'\n{3,}', '\n\n', steps)  # Normalize spacing
                    return steps
            
            return "Exploitation steps not explicitly documented in the exploit file."
        except Exception as e:
            logger.error(f"Error extracting exploitation steps: {str(e)}")
            return "Error extracting exploitation steps."


    async def make_request(self, session, url, method='GET', data=None, timeout=60):
        """Helper method to make requests with timeout handling"""
        try:
            async with session.request(method, url, data=data, timeout=timeout) as response:
                return await response.text(), response.status
        except asyncio.TimeoutError:
            logger.error(f"Request timeout for {url}")
            return None, None
        except Exception as e:
            logger.error(f"Error making request to {url}: {str(e)}")
            return None, None
            

    async def generate_report(self):
        """Generate detailed PDF report"""
        try:
            report_dir = "reports"
            os.makedirs(report_dir, exist_ok=True)
            filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            report_path = os.path.join(report_dir, filename)
            
            doc = SimpleDocTemplate(report_path, pagesize=letter)
            styles = getSampleStyleSheet()
            # Add custom style for exploit details
            styles.add(ParagraphStyle(
                name='ExploitDetail',
                parent=styles['Normal'],
                leftIndent=20,
                spaceBefore=10,
                spaceAfter=10,
                backColor=colors.lightgrey,
                borderPadding=5
            ))
            
            story = []
                
            # Title
            story.append(Paragraph(f"Security Assessment Report - {self.domain}", styles['Title']))
            story.append(Spacer(1, 20))
            
            # Server Information
            story.append(Paragraph("Server Information", styles['Heading1']))
            for key, value in self.server_info.items():
                if isinstance(value, dict):
                    story.append(Paragraph(f"{key}:", styles['Heading2']))
                    for k, v in value.items():
                        story.append(Paragraph(f"{k}: {v}", styles['Normal']))
                else:
                    story.append(Paragraph(f"{key}: {value}", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # DNS Records
            story.append(Paragraph("DNS Records", styles['Heading1']))
            for record in self.dns_records:
                story.append(Paragraph(f"Type: {record['type']}", styles['Heading2']))
                for r in record['records']:
                    story.append(Paragraph(f"- {r}", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # WHOIS Information
            story.append(Paragraph("WHOIS Information", styles['Heading1']))
            for key, value in self.whois_data.items():
                if value:
                    if isinstance(value, (list, tuple)):
                        story.append(Paragraph(f"{key}:", styles['Heading2']))
                        for item in value:
                            story.append(Paragraph(f"- {item}", styles['Normal']))
                    else:
                        story.append(Paragraph(f"{key}: {value}", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Port Scan Results
            if self.ports_scanned:
                story.append(Paragraph("Open Ports", styles['Heading1']))
                port_data = [["Port", "State", "Service", "Version"]]
                for port in self.ports_scanned:
                    port_data.append([
                        str(port['port']),
                        port['state'],
                        port['service'],
                        port.get('version', 'Unknown')
                    ])
                t = Table(port_data)
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(t)
                story.append(Spacer(1, 20))
            
                # Enhanced Vulnerabilities and Exploits Section
            story.append(Paragraph("Vulnerabilities and Exploit Analysis", styles['Heading1']))
            for vuln in self.vulnerabilities:
                # Vulnerability details
                story.append(Paragraph(f"Type: {vuln['type']}", styles['Heading2']))
                story.append(Paragraph(f"Severity: {vuln['severity']}", styles['Normal']))
                story.append(Paragraph(f"Description: {vuln['description']}", styles['Normal']))
                story.append(Paragraph(f"Remediation: {vuln['remediation']}", styles['Normal']))
                
                # Exploit details if available
                if 'exploits' in vuln and vuln['exploits']:
                    story.append(Paragraph("Associated Exploits:", styles['Heading3']))
                    for exploit in vuln['exploits']:
                        story.append(Paragraph(f"Exploit: {exploit['title']}", styles['ExploitDetail']))
                        if exploit['author']:
                            story.append(Paragraph(f"Author: {exploit['author']}", styles['ExploitDetail']))
                        if exploit['date']:
                            story.append(Paragraph(f"Date: {exploit['date']}", styles['ExploitDetail']))
                        if exploit['description']:
                            story.append(Paragraph(f"Description: {exploit['description']}", styles['ExploitDetail']))
                        
                        # Add exploitation steps in a highlighted box
                        if exploit['exploitation_steps']:
                            story.append(Paragraph("Exploitation Method:", styles['Heading4']))
                            story.append(Paragraph(exploit['exploitation_steps'], styles['ExploitDetail']))
                    
                story.append(Spacer(1, 20))
            
            # Build PDF
            doc.build(story)
            return filename
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            raise

# Routes
@app.route('/api/scan', methods=['POST'])
async def scan():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'error': 'Invalid JSON payload'
            }), 400
            
        target_url = data.get('url')
        
        if not target_url:
            return jsonify({
                'status': 'error',
                'error': 'No URL provided'
            }), 400
            
        if not target_url.startswith(('http://', 'https://')):
            return jsonify({
                'status': 'error',
                'error': 'Invalid URL format. Must start with http:// or https://'
            }), 400
        
        scanner = SecurityScanner(target_url)
        results = await scanner.full_scan()
        
        if not results:
            return jsonify({
                'status': 'error',
                'error': 'Scan completed but no results were generated'
            }), 500
        
        return jsonify({
            'status': 'success',
            'results': {
                'vulnerabilities': results.get('vulnerabilities', []),
                'exploits': results.get('exploits', []),
                'risk_level': results.get('risk_level', 'Unknown'),
                'scan_duration': results.get('scan_duration', 0),
                'report_path': results.get('report_path', '')
            }
        })
        
    except Exception as e:
        logger.error(f"Error in scan endpoint: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/report/<path:filename>')
def download_report(filename):
    try:
        if not filename.endswith('.pdf'):
            return jsonify({'error': 'Invalid file format'}), 400
            
        report_dir = os.path.abspath('reports')
        report_path = os.path.join(report_dir, filename)
        
        # Ensure the file exists
        if not os.path.exists(report_path):
            return jsonify({'error': 'Report not found'}), 404
            
        # Ensure the file is within the reports directory
        if not os.path.commonprefix([report_path, report_dir]) == report_dir:
            return jsonify({'error': 'Invalid report path'}), 400
            
        try:
            return send_file(
                report_path,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=filename
            )
        except Exception as e:
            logger.error(f"Error sending file: {str(e)}")
            return jsonify({'error': 'Error sending report file'}), 500
            
    except Exception as e:
        logger.error(f"Error downloading report: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False, port=5000)