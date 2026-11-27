"""HexStrike AI - http_testing module.

Extracted 1:1 from hexstrike_server.py lines 13277-14535.
Do not edit by hand: regenerate with scripts/splitter.py.
"""

import json
import time
from datetime import datetime
from flask import request
from flask import jsonify
import requests
import re
from urllib.parse import urljoin
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

from ..visual_engine import ModernVisualEngine
from ..core import app, logger
from ..intelligence.process_termination import env_manager
from ..intelligence.exploit_gen import execute_command, file_manager

# ============================================================================
# ENHANCED HTTP TESTING FRAMEWORK (BURP SUITE ALTERNATIVE)
# ============================================================================

class HTTPTestingFramework:
    """Advanced HTTP testing framework as Burp Suite alternative"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)'
        })
        self.proxy_history = []
        self.vulnerabilities = []
        self.match_replace_rules = []  # [{'where':'query|headers|body|url','pattern':'regex','replacement':'str'}]
        self.scope = None  # {'host': 'example.com', 'include_subdomains': True}
        self._req_id = 0

    def setup_proxy(self, proxy_port: int = 8080):
        """Setup HTTP proxy for request interception"""
        self.session.proxies = {
            'http': f'http://127.0.0.1:{proxy_port}',
            'https': f'http://127.0.0.1:{proxy_port}'
        }

    def intercept_request(self, url: str, method: str = 'GET', data: dict = None,
                         headers: dict = None, cookies: dict = None) -> dict:
        """Intercept and analyze HTTP requests"""
        try:
            if headers:
                self.session.headers.update(headers)
            if cookies:
                self.session.cookies.update(cookies)

            # Apply match/replace rules prior to sending
            url, data, send_headers = self._apply_match_replace(url, data, dict(self.session.headers))
            if headers:
                send_headers.update(headers)

            if method.upper() == 'GET':
                response = self.session.get(url, params=data, headers=send_headers, timeout=30)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=data, headers=send_headers, timeout=30)
            elif method.upper() == 'PUT':
                response = self.session.put(url, data=data, headers=send_headers, timeout=30)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=send_headers, timeout=30)
            else:
                response = self.session.request(method, url, data=data, headers=send_headers, timeout=30)

            # Store request/response in history
            self._req_id += 1
            request_data = {
                'id': self._req_id,
                'url': url,
                'method': method,
                'headers': dict(response.request.headers),
                'data': data,
                'timestamp': datetime.now().isoformat()
            }

            response_data = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text[:10000],  # Limit content size
                'size': len(response.content),
                'time': response.elapsed.total_seconds()
            }

            self.proxy_history.append({
                'request': request_data,
                'response': response_data
            })

            # Analyze for vulnerabilities
            self._analyze_response_for_vulns(url, response)

            return {
                'success': True,
                'request': request_data,
                'response': response_data,
                'vulnerabilities': self._get_recent_vulns()
            }

        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'HTTP-Framework', str(e))}")
            return {'success': False, 'error': str(e)}

    # ----------------- Match & Replace and Scope -----------------
    def set_match_replace_rules(self, rules: list):
        """Set match/replace rules. Each rule: {'where','pattern','replacement'}"""
        self.match_replace_rules = rules or []

    def set_scope(self, host: str, include_subdomains: bool = True):
        self.scope = {'host': host, 'include_subdomains': include_subdomains}

    def _in_scope(self, url: str) -> bool:
        if not self.scope:
            return True
        try:
            from urllib.parse import urlparse
            h = urlparse(url).hostname or ''
            target = self.scope.get('host','')
            if not h or not target:
                return True
            if h == target:
                return True
            if self.scope.get('include_subdomains') and h.endswith('.'+target):
                return True
        except Exception:
            return True
        return False

    def _apply_match_replace(self, url: str, data, headers: dict):
        import re
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        original_url = url
        out_headers = dict(headers)
        out_data = data
        for rule in self.match_replace_rules:
            where = (rule.get('where') or 'url').lower()
            pattern = rule.get('pattern') or ''
            repl = rule.get('replacement') or ''
            try:
                if where == 'url':
                    url = re.sub(pattern, repl, url)
                elif where == 'query':
                    pr = urlparse(url)
                    qs = parse_qsl(pr.query, keep_blank_values=True)
                    new_qs = []
                    for k, v in qs:
                        nk = re.sub(pattern, repl, k)
                        nv = re.sub(pattern, repl, v)
                        new_qs.append((nk, nv))
                    url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(new_qs), pr.fragment))
                elif where == 'headers':
                    out_headers = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_headers.items()}
                elif where == 'body':
                    if isinstance(out_data, dict):
                        out_data = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_data.items()}
                    elif isinstance(out_data, str):
                        out_data = re.sub(pattern, repl, out_data)
            except Exception:
                continue
        # Ensure scope restriction
        if not self._in_scope(url):
            logger.warning(f"{ModernVisualEngine.format_tool_status('HTTP-Framework', 'SKIPPED', f'Out of scope: {url}')}" )
            return original_url, data, headers
        return url, out_data, out_headers

    # ----------------- Repeater (custom send) -----------------
    def send_custom_request(self, request_spec: dict) -> dict:
        """Send a custom request with explicit fields, applying rules."""
        url = request_spec.get('url','')
        method = request_spec.get('method','GET')
        headers = request_spec.get('headers') or {}
        cookies = request_spec.get('cookies') or {}
        data = request_spec.get('data')
        return self.intercept_request(url, method, data, headers, cookies)

    # ----------------- Intruder (Sniper mode) -----------------
    def intruder_sniper(self, url: str, method: str = 'GET', location: str = 'query',
                        params: list = None, payloads: list = None, base_data: dict = None,
                        max_requests: int = 100) -> dict:
        """Simple fuzzing: iterate payloads over each parameter individually (Sniper)."""
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        params = params or []
        payloads = payloads or ["'\"<>`, ${7*7}"]
        base_data = base_data or {}
        interesting = []
        total = 0
        baseline = self.intercept_request(url, method, base_data)
        base_status = baseline.get('response',{}).get('status_code') if baseline.get('success') else None
        base_len = baseline.get('response',{}).get('size') if baseline.get('success') else None
        for p in params:
            for pay in payloads:
                if total >= max_requests:
                    break
                m_url = url
                m_data = dict(base_data)
                m_headers = {}
                if location == 'query':
                    pr = urlparse(url)
                    q = dict(parse_qsl(pr.query, keep_blank_values=True))
                    q[p] = pay
                    m_url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(q), pr.fragment))
                elif location == 'body':
                    m_data[p] = pay
                elif location == 'headers':
                    m_headers[p] = pay
                elif location == 'cookie':
                    self.session.cookies.set(p, pay)
                resp = self.intercept_request(m_url, method, m_data, m_headers)
                total += 1
                if not resp.get('success'):
                    continue
                r = resp['response']
                changed = (base_status is not None and r.get('status_code') != base_status) or (base_len is not None and abs(r.get('size',0) - base_len) > 150)
                reflected = pay in (r.get('content') or '')
                if changed or reflected:
                    interesting.append({
                        'param': p,
                        'payload': pay,
                        'status_code': r.get('status_code'),
                        'size': r.get('size'),
                        'reflected': reflected
                    })
        return {
            'success': True,
            'tested': total,
            'interesting': interesting[:50]
        }

    def _analyze_response_for_vulns(self, url: str, response):
        """Analyze HTTP response for common vulnerabilities"""
        vulns = []

        # Check for missing security headers
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME type sniffing protection missing',
            'X-XSS-Protection': 'XSS protection missing',
            'Strict-Transport-Security': 'HTTPS enforcement missing',
            'Content-Security-Policy': 'Content Security Policy missing'
        }

        for header, description in security_headers.items():
            if header not in response.headers:
                vulns.append({
                    'type': 'missing_security_header',
                    'severity': 'medium',
                    'description': description,
                    'url': url,
                    'header': header
                })

        # Check for sensitive information disclosure
        sensitive_patterns = [
            (r'password\s*[:=]\s*["\']?([^"\'\s]+)', 'Password disclosure'),
            (r'api[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)', 'API key disclosure'),
            (r'secret\s*[:=]\s*["\']?([^"\'\s]+)', 'Secret disclosure'),
            (r'token\s*[:=]\s*["\']?([^"\'\s]+)', 'Token disclosure')
        ]

        for pattern, description in sensitive_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                vulns.append({
                    'type': 'information_disclosure',
                    'severity': 'high',
                    'description': description,
                    'url': url,
                    'matches': matches[:5]  # Limit matches
                })

        # Check for SQL injection indicators
        sql_errors = [
            'SQL syntax error',
            'mysql_fetch_array',
            'ORA-01756',
            'Microsoft OLE DB Provider',
            'PostgreSQL query failed'
        ]

        for error in sql_errors:
            if error.lower() in response.text.lower():
                vulns.append({
                    'type': 'sql_injection_indicator',
                    'severity': 'high',
                    'description': f'Potential SQL injection: {error}',
                    'url': url
                })

        self.vulnerabilities.extend(vulns)

    def _get_recent_vulns(self, limit: int = 10):
        """Get recent vulnerabilities found"""
        return self.vulnerabilities[-limit:] if self.vulnerabilities else []

    def spider_website(self, base_url: str, max_depth: int = 3, max_pages: int = 100) -> dict:
        """Spider website to discover endpoints and forms"""
        try:
            discovered_urls = set()
            forms = []
            to_visit = [(base_url, 0)]
            visited = set()

            while to_visit and len(discovered_urls) < max_pages:
                current_url, depth = to_visit.pop(0)

                if current_url in visited or depth > max_depth:
                    continue

                visited.add(current_url)

                try:
                    response = self.session.get(current_url, timeout=10)
                    if response.status_code == 200:
                        discovered_urls.add(current_url)

                        # Parse HTML for links and forms
                        soup = BeautifulSoup(response.text, 'html.parser')

                        # Find all links
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            full_url = urljoin(current_url, href)

                            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                                if full_url not in visited and depth < max_depth:
                                    to_visit.append((full_url, depth + 1))

                        # Find all forms
                        for form in soup.find_all('form'):
                            form_data = {
                                'url': current_url,
                                'action': urljoin(current_url, form.get('action', '')),
                                'method': form.get('method', 'GET').upper(),
                                'inputs': []
                            }

                            for input_tag in form.find_all(['input', 'textarea', 'select']):
                                form_data['inputs'].append({
                                    'name': input_tag.get('name', ''),
                                    'type': input_tag.get('type', 'text'),
                                    'value': input_tag.get('value', '')
                                })

                            forms.append(form_data)

                except Exception as e:
                    logger.warning(f"Error spidering {current_url}: {str(e)}")
                    continue

            return {
                'success': True,
                'discovered_urls': list(discovered_urls),
                'forms': forms,
                'total_pages': len(discovered_urls),
                'vulnerabilities': self._get_recent_vulns()
            }

        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'Spider', str(e))}")
            return {'success': False, 'error': str(e)}

class BrowserAgent:
    """AI-powered browser agent for web application testing and inspection"""

    def __init__(self):
        self.driver = None
        self.screenshots = []
        self.page_sources = []
        self.network_logs = []

    def setup_browser(self, headless: bool = True, proxy_port: int = None):
        """Setup Chrome browser with security testing options"""
        try:
            chrome_options = Options()

            if headless:
                chrome_options.add_argument('--headless')

            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--user-agent=HexStrike-BrowserAgent/1.0 (Security Testing)')

            # Enable logging
            chrome_options.add_argument('--enable-logging')
            chrome_options.add_argument('--log-level=0')

            # Security testing options
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--ignore-ssl-errors')

            if proxy_port:
                chrome_options.add_argument(f'--proxy-server=http://127.0.0.1:{proxy_port}')

            # Enable network logging
            chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})

            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)

            logger.info(f"{ModernVisualEngine.format_tool_status('BrowserAgent', 'RUNNING', 'Chrome Browser Initialized')}")
            return True

        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'BrowserAgent', str(e))}")
            return False

    def navigate_and_inspect(self, url: str, wait_time: int = 5) -> dict:
        """Navigate to URL and perform comprehensive inspection"""
        try:
            if not self.driver:
                if not self.setup_browser():
                    return {'success': False, 'error': 'Failed to setup browser'}

            nav_command = f'Navigate to {url}'
            logger.info(f"{ModernVisualEngine.format_command_execution(nav_command, 'STARTING')}")

            # Navigate to URL
            self.driver.get(url)
            time.sleep(wait_time)

            # Take screenshot
            screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
            self.driver.save_screenshot(screenshot_path)
            self.screenshots.append(screenshot_path)

            # Get page source
            page_source = self.driver.page_source
            self.page_sources.append({
                'url': url,
                'source': page_source[:50000],  # Limit size
                'timestamp': datetime.now().isoformat()
            })

            # Extract page information
            page_info = {
                'title': self.driver.title,
                'url': self.driver.current_url,
                'cookies': [{'name': c['name'], 'value': c['value'], 'domain': c['domain']}
                           for c in self.driver.get_cookies()],
                'local_storage': self._get_local_storage(),
                'session_storage': self._get_session_storage(),
                'forms': self._extract_forms(),
                'links': self._extract_links(),
                'inputs': self._extract_inputs(),
                'scripts': self._extract_scripts(),
                'network_requests': self._get_network_logs(),
                'console_errors': self._get_console_errors()
            }

            # Analyze for security issues
            security_analysis = self._analyze_page_security(page_source, page_info)
            # Merge extended passive analysis
            extended_passive = self._extended_passive_analysis(page_info, page_source)
            security_analysis['issues'].extend(extended_passive['issues'])
            security_analysis['total_issues'] = len(security_analysis['issues'])
            security_analysis['security_score'] = max(0, 100 - (security_analysis['total_issues'] * 5))
            security_analysis['passive_modules'] = extended_passive.get('modules', [])

            logger.info(f"{ModernVisualEngine.format_tool_status('BrowserAgent', 'SUCCESS', url)}")

            return {
                'success': True,
                'page_info': page_info,
                'security_analysis': security_analysis,
                'screenshot': screenshot_path,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'BrowserAgent', str(e))}")
            return {'success': False, 'error': str(e)}

    # ---------------------- Browser Deep Introspection Helpers ----------------------
    def _get_console_errors(self) -> list:
        """Collect console errors & warnings (if supported)"""
        try:
            logs = self.driver.get_log('browser')
            out = []
            for entry in logs[-100:]:
                lvl = entry.get('level', '')
                if lvl in ('SEVERE', 'WARNING'):
                    out.append({'level': lvl, 'message': entry.get('message', '')[:500]})
            return out
        except Exception:
            return []

    def _analyze_cookies(self, cookies: list) -> list:
        issues = []
        for ck in cookies:
            name = ck.get('name','')
            # Selenium cookie dict may lack flags; attempt JS check if not present
            # (we keep lightweight – deeper flag detection requires CDP)
            if name.lower() in ('sessionid','phpseSSID','jsessionid') and len(ck.get('value','')) < 16:
                issues.append({'type':'weak_session_cookie','severity':'medium','description':f'Session cookie {name} appears short'})
        return issues

    def _analyze_security_headers(self, page_source: str, page_info: dict) -> list:
        # We cannot directly read response headers via Selenium; attempt a lightweight fetch with requests
        issues = []
        try:
            resp = requests.get(page_info.get('url',''), timeout=10, verify=False)
            headers = {k.lower():v for k,v in resp.headers.items()}
            required = {
                'content-security-policy':'CSP header missing (XSS mitigation)',
                'x-frame-options':'X-Frame-Options missing (Clickjacking risk)',
                'x-content-type-options':'X-Content-Type-Options missing (MIME sniffing risk)',
                'referrer-policy':'Referrer-Policy missing (leaky referrers)',
                'strict-transport-security':'HSTS missing (HTTPS downgrade risk)'
            }
            for key, desc in required.items():
                if key not in headers:
                    issues.append({'type':'missing_security_header','severity':'medium','description':desc,'header':key})
            # Weak CSP heuristic
            csp = headers.get('content-security-policy','')
            if csp and "unsafe-inline" in csp:
                issues.append({'type':'weak_csp','severity':'low','description':'CSP allows unsafe-inline scripts'})
        except Exception:
            pass
        return issues

    def _detect_mixed_content(self, page_info: dict) -> list:
        issues = []
        try:
            page_url = page_info.get('url','')
            if page_url.startswith('https://'):
                for req in page_info.get('network_requests', [])[:200]:
                    u = req.get('url','')
                    if u.startswith('http://'):
                        issues.append({'type':'mixed_content','severity':'medium','description':f'HTTP resource loaded over HTTPS page: {u[:100]}'})
        except Exception:
            pass
        return issues

    def _extended_passive_analysis(self, page_info: dict, page_source: str) -> dict:
        modules = []
        issues = []
        # Cookies
        cookie_issues = self._analyze_cookies(page_info.get('cookies', []))
        if cookie_issues:
            issues.extend(cookie_issues); modules.append('cookie_analysis')
        # Headers
        header_issues = self._analyze_security_headers(page_source, page_info)
        if header_issues:
            issues.extend(header_issues); modules.append('security_headers')
        # Mixed content
        mixed = self._detect_mixed_content(page_info)
        if mixed:
            issues.extend(mixed); modules.append('mixed_content')
        # Console errors may hint at DOM XSS sinks
        if page_info.get('console_errors'):
            modules.append('console_log_capture')
        return {'issues': issues, 'modules': modules}

    def run_active_tests(self, page_info: dict, payload: str = '<hexstrikeXSSTest123>') -> dict:
        """Very lightweight active tests (reflection check) - safe mode.
        Only GET forms with text inputs to avoid state-changing operations."""
        findings = []
        tested = 0
        for form in page_info.get('forms', []):
            if form.get('method','GET').upper() != 'GET':
                continue
            params = []
            for inp in form.get('inputs', [])[:3]:  # limit
                if inp.get('type','text') in ('text','search'):
                    params.append(f"{inp.get('name','param')}={payload}")
            if not params:
                continue
            action = form.get('action') or page_info.get('url','')
            if action.startswith('/'):
                # relative
                base = page_info.get('url','')
                try:
                    from urllib.parse import urljoin
                    action = urljoin(base, action)
                except Exception:
                    pass
            test_url = action + ('&' if '?' in action else '?') + '&'.join(params)
            try:
                r = requests.get(test_url, timeout=8, verify=False)
                tested += 1
                if payload in r.text:
                    findings.append({'type':'reflected_xss','severity':'high','description':'Payload reflected in response','url':test_url})
            except Exception:
                continue
            if tested >= 5:
                break
        return {'active_findings': findings, 'tested_forms': tested}

    def _get_local_storage(self) -> dict:
        """Extract local storage data"""
        try:
            return self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < localStorage.length; i++) {
                    var key = localStorage.key(i);
                    storage[key] = localStorage.getItem(key);
                }
                return storage;
            """)
        except:
            return {}

    def _get_session_storage(self) -> dict:
        """Extract session storage data"""
        try:
            return self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < sessionStorage.length; i++) {
                    var key = sessionStorage.key(i);
                    storage[key] = sessionStorage.getItem(key);
                }
                return storage;
            """)
        except:
            return {}

    def _extract_forms(self) -> list:
        """Extract all forms from the page"""
        forms = []
        try:
            form_elements = self.driver.find_elements(By.TAG_NAME, 'form')
            for form in form_elements:
                form_data = {
                    'action': form.get_attribute('action') or '',
                    'method': form.get_attribute('method') or 'GET',
                    'inputs': []
                }

                inputs = form.find_elements(By.TAG_NAME, 'input')
                for input_elem in inputs:
                    form_data['inputs'].append({
                        'name': input_elem.get_attribute('name') or '',
                        'type': input_elem.get_attribute('type') or 'text',
                        'value': input_elem.get_attribute('value') or ''
                    })

                forms.append(form_data)
        except:
            pass

        return forms

    def _extract_links(self) -> list:
        """Extract all links from the page"""
        links = []
        try:
            link_elements = self.driver.find_elements(By.TAG_NAME, 'a')
            for link in link_elements[:50]:  # Limit to 50 links
                href = link.get_attribute('href')
                if href:
                    links.append({
                        'href': href,
                        'text': link.text[:100]  # Limit text length
                    })
        except:
            pass

        return links

    def _extract_inputs(self) -> list:
        """Extract all input elements"""
        inputs = []
        try:
            input_elements = self.driver.find_elements(By.TAG_NAME, 'input')
            for input_elem in input_elements:
                inputs.append({
                    'name': input_elem.get_attribute('name') or '',
                    'type': input_elem.get_attribute('type') or 'text',
                    'id': input_elem.get_attribute('id') or '',
                    'placeholder': input_elem.get_attribute('placeholder') or ''
                })
        except:
            pass

        return inputs

    def _extract_scripts(self) -> list:
        """Extract script sources and inline scripts"""
        scripts = []
        try:
            script_elements = self.driver.find_elements(By.TAG_NAME, 'script')
            for script in script_elements[:20]:  # Limit to 20 scripts
                src = script.get_attribute('src')
                if src:
                    scripts.append({'type': 'external', 'src': src})
                else:
                    content = script.get_attribute('innerHTML')
                    if content and len(content) > 10:
                        scripts.append({
                            'type': 'inline',
                            'content': content[:1000]  # Limit content
                        })
        except:
            pass

        return scripts

    def _get_network_logs(self) -> list:
        """Get network request logs"""
        try:
            logs = self.driver.get_log('performance')
            network_requests = []

            for log in logs[-50:]:  # Last 50 logs
                message = json.loads(log['message'])
                if message['message']['method'] == 'Network.responseReceived':
                    response = message['message']['params']['response']
                    network_requests.append({
                        'url': response['url'],
                        'status': response['status'],
                        'mimeType': response['mimeType'],
                        'headers': response.get('headers', {})
                    })

            return network_requests
        except:
            return []

    def _analyze_page_security(self, page_source: str, page_info: dict) -> dict:
        """Analyze page for security vulnerabilities"""
        issues = []

        # Check for sensitive data in local/session storage
        for storage_type, storage_data in [('localStorage', page_info.get('local_storage', {})),
                                          ('sessionStorage', page_info.get('session_storage', {}))]:
            for key, value in storage_data.items():
                if any(sensitive in key.lower() for sensitive in ['password', 'token', 'secret', 'key']):
                    issues.append({
                        'type': 'sensitive_data_storage',
                        'severity': 'high',
                        'description': f'Sensitive data found in {storage_type}: {key}',
                        'location': storage_type
                    })

        # Check for forms without CSRF protection
        for form in page_info.get('forms', []):
            has_csrf = any('csrf' in input_data['name'].lower() or 'token' in input_data['name'].lower()
                          for input_data in form['inputs'])
            if not has_csrf and form['method'].upper() == 'POST':
                issues.append({
                    'type': 'missing_csrf_protection',
                    'severity': 'medium',
                    'description': 'Form without CSRF protection detected',
                    'form_action': form['action']
                })

        # Check for inline JavaScript
        inline_scripts = [s for s in page_info.get('scripts', []) if s['type'] == 'inline']
        if inline_scripts:
            issues.append({
                'type': 'inline_javascript',
                'severity': 'low',
                'description': f'Found {len(inline_scripts)} inline JavaScript blocks',
                'count': len(inline_scripts)
            })

        return {
            'total_issues': len(issues),
            'issues': issues,
            'security_score': max(0, 100 - (len(issues) * 10))  # Simple scoring
        }

    def close_browser(self):
        """Close the browser instance"""
        if self.driver:
            self.driver.quit()
            self.driver = None
            logger.info(f"{ModernVisualEngine.format_tool_status('BrowserAgent', 'SUCCESS', 'Browser Closed')}")

# Global instances
http_framework = HTTPTestingFramework()
browser_agent = BrowserAgent()

@app.route("/api/tools/http-framework", methods=["POST"])
def http_framework_endpoint():
    """Enhanced HTTP testing framework (Burp Suite alternative)"""
    try:
        params = request.json
        action = params.get("action", "request")  # request, spider, proxy_history, set_rules, set_scope, repeater, intruder
        url = params.get("url", "")
        method = params.get("method", "GET")
        data = params.get("data", {})
        headers = params.get("headers", {})
        cookies = params.get("cookies", {})

        logger.info(f"{ModernVisualEngine.create_section_header('HTTP FRAMEWORK', '🔥', 'FIRE_RED')}")

        if action == "request":
            if not url:
                return jsonify({"error": "URL parameter is required for request action"}), 400

            request_command = f"{method} {url}"
            logger.info(f"{ModernVisualEngine.format_command_execution(request_command, 'STARTING')}")
            result = http_framework.intercept_request(url, method, data, headers, cookies)

            if result.get("success"):
                logger.info(f"{ModernVisualEngine.format_tool_status('HTTP-Framework', 'SUCCESS', url)}")
            else:
                logger.error(f"{ModernVisualEngine.format_tool_status('HTTP-Framework', 'FAILED', url)}")

            return jsonify(result)

        elif action == "spider":
            if not url:
                return jsonify({"error": "URL parameter is required for spider action"}), 400

            max_depth = params.get("max_depth", 3)
            max_pages = params.get("max_pages", 100)

            spider_command = f"Spider {url}"
            logger.info(f"{ModernVisualEngine.format_command_execution(spider_command, 'STARTING')}")
            result = http_framework.spider_website(url, max_depth, max_pages)

            if result.get("success"):
                total_pages = result.get("total_pages", 0)
                pages_info = f"{total_pages} pages"
                logger.info(f"{ModernVisualEngine.format_tool_status('HTTP-Spider', 'SUCCESS', pages_info)}")
            else:
                logger.error(f"{ModernVisualEngine.format_tool_status('HTTP-Spider', 'FAILED', url)}")

            return jsonify(result)

        elif action == "proxy_history":
            return jsonify({
                "success": True,
                "history": http_framework.proxy_history[-100:],  # Last 100 requests
                "total_requests": len(http_framework.proxy_history),
                "vulnerabilities": http_framework.vulnerabilities,
            })

        elif action == "set_rules":
            rules = params.get("rules", [])
            http_framework.set_match_replace_rules(rules)
            return jsonify({"success": True, "rules_set": len(rules)})

        elif action == "set_scope":
            scope_host = params.get("host")
            include_sub = params.get("include_subdomains", True)
            if not scope_host:
                return jsonify({"error": "host parameter required"}), 400
            http_framework.set_scope(scope_host, include_sub)
            return jsonify({"success": True, "scope": http_framework.scope})

        elif action == "repeater":
            request_spec = params.get("request") or {}
            result = http_framework.send_custom_request(request_spec)
            return jsonify(result)

        elif action == "intruder":
            if not url:
                return jsonify({"error": "URL parameter required"}), 400
            method = params.get("method", "GET")
            location = params.get("location", "query")
            fuzz_params = params.get("params", [])
            payloads = params.get("payloads", [])
            base_data = params.get("base_data", {})
            max_requests = params.get("max_requests", 100)
            result = http_framework.intruder_sniper(
                url, method, location, fuzz_params, payloads, base_data, max_requests
            )
            return jsonify(result)

        else:
            return jsonify({"error": f"Unknown action: {action}"}), 400

    except Exception as e:
        logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'HTTP-Framework', str(e))}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/browser-agent", methods=["POST"])
def browser_agent_endpoint():
    """AI-powered browser agent for web application inspection"""
    try:
        params = request.json or {}
        action = params.get("action", "navigate")  # navigate, screenshot, close
        url = params.get("url", "")
        headless = params.get("headless", True)
        wait_time = params.get("wait_time", 5)
        proxy_port = params.get("proxy_port")
        active_tests = params.get("active_tests", False)

        logger.info(
            f"{ModernVisualEngine.create_section_header('BROWSER AGENT', '🌐', 'CRIMSON')}"
        )

        if action == "navigate":
            if not url:
                return (
                    jsonify({"error": "URL parameter is required for navigate action"}),
                    400,
                )

            # Setup browser if not already done
            if not browser_agent.driver:
                setup_success = browser_agent.setup_browser(headless, proxy_port)
                if not setup_success:
                    return jsonify({"error": "Failed to setup browser"}), 500

            result = browser_agent.navigate_and_inspect(url, wait_time)
            if result.get("success") and active_tests:
                active_results = browser_agent.run_active_tests(
                    result.get("page_info", {})
                )
                result["active_tests"] = active_results
                if active_results["active_findings"]:
                    logger.warning(
                        ModernVisualEngine.format_error_card(
                            "WARNING",
                            "BrowserAgent",
                            f"Active findings: {len(active_results['active_findings'])}",
                        )
                    )
            return jsonify(result)

        elif action == "screenshot":
            if not browser_agent.driver:
                return (
                    jsonify(
                        {"error": "Browser not initialized. Use navigate action first."}
                    ),
                    400,
                )

            screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
            browser_agent.driver.save_screenshot(screenshot_path)

            return jsonify(
                {
                    "success": True,
                    "screenshot": screenshot_path,
                    "current_url": browser_agent.driver.current_url,
                    "timestamp": datetime.now().isoformat(),
                }
            )

        elif action == "close":
            browser_agent.close_browser()
            return jsonify({"success": True, "message": "Browser closed successfully"})

        elif action == "status":
            return jsonify(
                {
                    "success": True,
                    "browser_active": browser_agent.driver is not None,
                    "screenshots_taken": len(browser_agent.screenshots),
                    "pages_visited": len(browser_agent.page_sources),
                }
            )

        else:
            return jsonify({"error": f"Unknown action: {action}"}), 400

    except Exception as e:
        logger.error(
            f"{ModernVisualEngine.format_error_card('ERROR', 'BrowserAgent', str(e))}"
        )
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/burpsuite-alternative", methods=["POST"])
def burpsuite_alternative():
    """Comprehensive Burp Suite alternative combining HTTP framework and browser agent"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "comprehensive")  # comprehensive, spider, passive, active
        headless = params.get("headless", True)
        max_depth = params.get("max_depth", 3)
        max_pages = params.get("max_pages", 50)

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        logger.info(f"{ModernVisualEngine.create_section_header('BURP SUITE ALTERNATIVE', '🔥', 'BLOOD_RED')}")
        scan_message = f'Starting {scan_type} scan of {target}'
        logger.info(f"{ModernVisualEngine.format_highlighted_text(scan_message, 'RED')}")

        results = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'success': True
        }

        # Phase 1: Browser-based reconnaissance
        if scan_type in ['comprehensive', 'spider']:
            logger.info(f"{ModernVisualEngine.format_tool_status('BrowserAgent', 'RUNNING', 'Reconnaissance Phase')}")

            if not browser_agent.driver:
                browser_agent.setup_browser(headless)

            browser_result = browser_agent.navigate_and_inspect(target)
            results['browser_analysis'] = browser_result

        # Phase 2: HTTP spidering
        if scan_type in ['comprehensive', 'spider']:
            logger.info(f"{ModernVisualEngine.format_tool_status('HTTP-Spider', 'RUNNING', 'Discovery Phase')}")

            spider_result = http_framework.spider_website(target, max_depth, max_pages)
            results['spider_analysis'] = spider_result

        # Phase 3: Vulnerability analysis
        if scan_type in ['comprehensive', 'active']:
            logger.info(f"{ModernVisualEngine.format_tool_status('VulnScanner', 'RUNNING', 'Analysis Phase')}")

            # Test discovered endpoints
            discovered_urls = results.get('spider_analysis', {}).get('discovered_urls', [target])
            vuln_results = []

            for url in discovered_urls[:20]:  # Limit to 20 URLs
                test_result = http_framework.intercept_request(url)
                if test_result.get('success'):
                    vuln_results.append(test_result)

            results['vulnerability_analysis'] = {
                'tested_urls': len(vuln_results),
                'total_vulnerabilities': len(http_framework.vulnerabilities),
                'recent_vulnerabilities': http_framework._get_recent_vulns(20)
            }

        # Generate summary
        total_vulns = len(http_framework.vulnerabilities)
        vuln_summary = {}
        for vuln in http_framework.vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            vuln_summary[severity] = vuln_summary.get(severity, 0) + 1

        results['summary'] = {
            'total_vulnerabilities': total_vulns,
            'vulnerability_breakdown': vuln_summary,
            'pages_analyzed': len(results.get('spider_analysis', {}).get('discovered_urls', [])),
            'security_score': max(0, 100 - (total_vulns * 5))
        }

        # Display summary with enhanced colors
        logger.info(f"{ModernVisualEngine.create_section_header('SCAN COMPLETE', '✅', 'SUCCESS')}")
        vuln_message = f'Found {total_vulns} vulnerabilities'
        color_choice = 'YELLOW' if total_vulns > 0 else 'GREEN'
        logger.info(f"{ModernVisualEngine.format_highlighted_text(vuln_message, color_choice)}")

        for severity, count in vuln_summary.items():
            logger.info(f"  {ModernVisualEngine.format_vulnerability_severity(severity, count)}")

        return jsonify(results)

    except Exception as e:
        logger.error(f"{ModernVisualEngine.format_error_card('CRITICAL', 'BurpAlternative', str(e))}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
        logger.error(f"💥 Error in burpsuite endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/zap", methods=["POST"])
def zap():
    """Execute OWASP ZAP with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "baseline")
        api_key = params.get("api_key", "")
        daemon = params.get("daemon", False)
        port = params.get("port", "8090")
        host = params.get("host", "0.0.0.0")
        format_type = params.get("format", "xml")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target and scan_type != "daemon":
            logger.warning("🎯 ZAP called without target parameter")
            return jsonify({
                "error": "Target parameter is required for scans"
            }), 400

        if daemon:
            command = f"zaproxy -daemon -host {host} -port {port}"
            if api_key:
                command += f" -config api.key={api_key}"
        else:
            command = f"zaproxy -cmd -quickurl {target}"

            if format_type:
                command += f" -quickout {format_type}"

            if output_file:
                command += f" -quickprogress -dir \"{output_file}\""

            if api_key:
                command += f" -config api.key={api_key}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting ZAP scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 ZAP scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in zap endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wafw00f", methods=["POST"])
def wafw00f():
    """Execute wafw00f to identify and fingerprint WAF products with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🛡️ Wafw00f called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"wafw00f {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🛡️ Starting Wafw00f WAF detection: {target}")
        result = execute_command(command)
        logger.info(f"📊 Wafw00f completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in wafw00f endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/fierce", methods=["POST"])
def fierce():
    """Execute fierce for DNS reconnaissance with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        dns_server = params.get("dns_server", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Fierce called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400

        command = f"fierce --domain {domain}"

        if dns_server:
            command += f" --dns-servers {dns_server}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Fierce DNS recon: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Fierce completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in fierce endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dnsenum", methods=["POST"])
def dnsenum():
    """Execute dnsenum for DNS enumeration with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        dns_server = params.get("dns_server", "")
        wordlist = params.get("wordlist", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 DNSenum called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400

        command = f"dnsenum {domain}"

        if dns_server:
            command += f" --dnsserver {dns_server}"

        if wordlist:
            command += f" --file {wordlist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting DNSenum: {domain}")
        result = execute_command(command)
        logger.info(f"📊 DNSenum completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dnsenum endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Python Environment Management Endpoints
@app.route("/api/python/install", methods=["POST"])
def install_python_package():
    """Install a Python package in a virtual environment"""
    try:
        params = request.json
        package = params.get("package", "")
        env_name = params.get("env_name", "default")

        if not package:
            return jsonify({"error": "Package name is required"}), 400

        logger.info(f"📦 Installing Python package: {package} in env {env_name}")
        success = env_manager.install_package(env_name, package)

        if success:
            return jsonify({
                "success": True,
                "message": f"Package {package} installed successfully",
                "env_name": env_name
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to install package {package}"
            }), 500

    except Exception as e:
        logger.error(f"💥 Error installing Python package: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/python/execute", methods=["POST"])
def execute_python_script():
    """Execute a Python script in a virtual environment"""
    try:
        params = request.json
        script = params.get("script", "")
        env_name = params.get("env_name", "default")
        filename = params.get("filename", f"script_{int(time.time())}.py")

        if not script:
            return jsonify({"error": "Script content is required"}), 400

        # Create script file
        script_result = file_manager.create_file(filename, script)
        if not script_result["success"]:
            return jsonify(script_result), 500

        # Get Python path for environment
        python_path = env_manager.get_python_path(env_name)
        script_path = script_result["path"]

        # Execute script
        command = f"{python_path} {script_path}"
        logger.info(f"🐍 Executing Python script in env {env_name}: {filename}")
        result = execute_command(command, use_cache=False)

        # Clean up script file
        file_manager.delete_file(filename)

        result["env_name"] = env_name
        result["script_filename"] = filename
        logger.info(f"📊 Python script execution completed")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error executing Python script: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
