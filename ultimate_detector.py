"""
ULTIMATE PHISHING DETECTOR - ENHANCED
With parallel processing, smart caching, dead site handling, and BALANCED thresholds
"""
import time
import json
import re
import os
import hashlib
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import torch
import requests
from bs4 import BeautifulSoup
from src.api_manager import APIManager
from src.initial_transformer import InitialTransformer


class CircuitBreaker:
    """Prevents repeatedly trying dead sites"""
    def __init__(self, failure_threshold=3, reset_timeout=300):
        self.failures = {}
        self.threshold = failure_threshold
        self.reset_timeout = reset_timeout

    def can_try(self, url):
        if url in self.failures:
            failures, last_time = self.failures[url]
            if failures >= self.threshold:
                if time.time() - last_time < self.reset_timeout:
                    return False
                else:
                    del self.failures[url]
        return True

    def record_failure(self, url):
        if url not in self.failures:
            self.failures[url] = [1, time.time()]
        else:
            failures, _ = self.failures[url]
            self.failures[url] = [failures + 1, time.time()]


class OptimizedPageAnalyzer:
    """Page analyzer with dead site handling and caching"""

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

        # Sensitive field patterns
        self.sensitive_fields = {
            'password': ['password', 'passwd', 'pwd'],
            'credit_card': ['credit', 'card', 'cc', 'cardnumber'],
            'cvv': ['cvv', 'cvc', 'security code'],
            'ssn': ['ssn', 'social security', 'tax id']
        }

        # Caches
        self.success_cache = {}
        self.failure_cache = {}
        self.circuit_breaker = CircuitBreaker()
        self.cache_ttl = 3600  # 1 hour

    def _is_site_alive(self, url, timeout=2):
        """Quick HEAD request to check site"""
        try:
            response = self.session.head(url, timeout=timeout, allow_redirects=True)
            return response.status_code == 200
        except:
            return False

    def _get_adaptive_timeout(self, url):
        """Adjust timeout based on domain"""
        domain = urlparse(url).netloc
        if any(trusted in domain for trusted in ['google.com', 'github.com']):
            return 3
        elif any(susp in domain for susp in ['.cfd', '.sbs', '.click']):
            return 5
        return self.timeout

    def analyze_page(self, url, expected_brand=None):
        """Optimized page analysis"""

        # Check cache first
        url_hash = hashlib.md5(url.encode()).hexdigest()
        if url_hash in self.success_cache:
            return self.success_cache[url_hash]

        # Circuit breaker check
        if not self.circuit_breaker.can_try(url):
            return {
                'fetch_success': False,
                'error': 'Circuit breaker open',
                'phishing_score': 0.0,
                'note': 'Site previously failed multiple times'
            }

        # Quick alive check
        if not self._is_site_alive(url):
            self.circuit_breaker.record_failure(url)
            return {
                'fetch_success': False,
                'error': 'Site unreachable',
                'phishing_score': 0.0
            }

        try:
            # Fetch page with adaptive timeout
            timeout = self._get_adaptive_timeout(url)
            response = self.session.get(url, timeout=timeout, allow_redirects=True)

            if response.status_code != 200:
                return {
                    'fetch_success': False,
                    'error': f'HTTP {response.status_code}',
                    'phishing_score': 0.0
                }

            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')

            # Analyze page
            results = {
                'fetch_success': True,
                'status_code': response.status_code,
                'ssl_valid': response.url.startswith('https://'),
                'has_login_form': False,
                'has_password_field': False,
                'external_form_action': False,
                'sensitive_fields_found': [],
                'suspicious_indicators': [],
                'phishing_score': 0.0
            }

            # Check forms
            forms = soup.find_all('form')
            for form in forms:
                # Check for password field
                if form.find('input', {'type': 'password'}):
                    results['has_password_field'] = True
                    results['has_login_form'] = True

                # Check form action
                action = form.get('action', '')
                if action:
                    if not action.startswith('http'):
                        action = urljoin(url, action)
                    action_domain = urlparse(action).netloc
                    base_domain = urlparse(url).netloc

                    if action_domain and action_domain != base_domain:
                        results['external_form_action'] = True
                        results['suspicious_indicators'].append(f"External form: {action_domain}")

                # Check inputs for sensitive fields
                for input_field in form.find_all('input'):
                    input_name = input_field.get('name', '').lower()
                    for field_type, patterns in self.sensitive_fields.items():
                        if any(p in input_name for p in patterns):
                            results['sensitive_fields_found'].append(field_type)

            # Check for iframes
            iframes = soup.find_all('iframe')
            for iframe in iframes:
                width = iframe.get('width', '')
                height = iframe.get('height', '')
                if width in ['0', '1'] or height in ['0', '1']:
                    results['suspicious_indicators'].append('Hidden iframe')

            # Calculate phishing score (0-1)
            score = 0.0
            if results['has_password_field'] and not results['ssl_valid']:
                score += 0.3
            if results['external_form_action']:
                score += 0.4
            if 'credit_card' in results['sensitive_fields_found']:
                score += 0.5
            if 'ssn' in results['sensitive_fields_found']:
                score += 0.5
            if len(results['suspicious_indicators']) > 2:
                score += 0.2

            results['phishing_score'] = min(score, 1.0)

            # Cache successful result
            self.success_cache[url_hash] = results
            return results

        except Exception as e:
            self.circuit_breaker.record_failure(url)
            return {
                'fetch_success': False,
                'error': str(e),
                'phishing_score': 0.0
            }


class EnhancedUltimatePhishingDetector:
    """Complete phishing detector with all layers - BALANCED version"""

    def __init__(self, model_path='src/initial_model.pkl'):
        print("🚀 Initializing Enhanced Ultimate Phishing Detector...")

        # Load AI model
        print("1️⃣ Loading AI model...")
        self.ai_model = InitialTransformer(device='auto')
        try:
            self.ai_model.load(model_path)
            print(f"   ✅ AI model loaded from {model_path}")
        except Exception as e:
            print(f"   ⚠️ Could not load model: {e}")
            self.ai_model = None

        # Initialize API manager
        print("2️⃣ Initializing API manager...")
        self.api = APIManager()

        # Load brand database
        print("3️⃣ Loading brand database...")
        self.brand_db = self._load_brand_database()
        self._create_domain_mappings()

        # Initialize page analyzer
        print("4️⃣ Initializing page analyzer...")
        self.page_analyzer = OptimizedPageAnalyzer()

        # Trusted domains whitelist
        self.trusted_domains = self._load_trusted_domains()

        print(f"✅ System ready with {len(self.trusted_domains)} trusted domains!")

    def _load_brand_database(self):
        """Load brand database from brands.json"""
        try:
            with open('src/brands.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"   ⚠️ Could not load brands.json: {e}")
            return {}

    def _create_domain_mappings(self):
        """Create domain mappings from brand database"""
        self.official_domains = set()
        self.brand_patterns = {}
        self.brand_weights = {}

        for brand_name, brand_info in self.brand_db.items():
            # Add official domains
            for domain in brand_info.get('official_domains', []):
                self.official_domains.add(self._clean_domain(domain))

            # Store patterns and weight
            self.brand_patterns[brand_name] = brand_info.get('common_variations', [])
            self.brand_weights[brand_name] = brand_info.get('weight', 0.8)

    def _clean_domain(self, domain):
        """Clean domain for comparison"""
        domain = domain.lower().strip()
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain

    def _load_trusted_domains(self):
        """Load trusted domains whitelist"""
        trusted = set()

        # Add official domains from brands
        for brand_name, brand_info in self.brand_db.items():
            for domain in brand_info.get('official_domains', []):
                trusted.add(self._clean_domain(domain))

        # Add common trusted domains (with and without www)
        common = [
            'google.com', 'www.google.com',
            'youtube.com', 'www.youtube.com',
            'facebook.com', 'www.facebook.com',
            'amazon.com', 'www.amazon.com',
            'github.com', 'www.github.com',
            'stackoverflow.com', 'www.stackoverflow.com',
            'wikipedia.org', 'www.wikipedia.org',
            'microsoft.com', 'www.microsoft.com',
            'apple.com', 'www.apple.com',
            'paypal.com', 'www.paypal.com',
            'twitter.com', 'www.twitter.com',
            'linkedin.com', 'www.linkedin.com',
            'netflix.com', 'www.netflix.com',
            'instagram.com', 'www.instagram.com',
            'reddit.com', 'www.reddit.com',
            'ebay.com', 'www.ebay.com',
            'zoom.us', 'www.zoom.us',
            'office.com', 'www.office.com',
            'live.com', 'www.live.com',
            'bing.com', 'www.bing.com',
            'cloudflare.com', 'www.cloudflare.com',
            'medium.com', 'www.medium.com',
            'nytimes.com', 'www.nytimes.com',
            'bbc.com', 'www.bbc.com',
            'cnn.com', 'www.cnn.com',
            'imdb.com', 'www.imdb.com',
            'whatsapp.com', 'www.whatsapp.com',
            'spotify.com', 'www.spotify.com',
            'telegram.org', 'www.telegram.org',
            'dropbox.com', 'www.dropbox.com'
        ]
        for domain in common:
            trusted.add(self._clean_domain(domain))

        return list(trusted)

    def get_trusted_domains(self):
        """Public method to access trusted domains"""
        return self.trusted_domains

    def _analyze_brand_impersonation(self, url, domain):
        """Check if URL is impersonating a brand"""
        clean_domain = self._clean_domain(domain)
        domain_parts = clean_domain.split('.')
        main_domain = domain_parts[0] if domain_parts else ''

        results = {
            'is_impersonation': False,
            'impersonated_brand': None,
            'method': None,
            'confidence': 0.0,
            'detected_brands': []
        }

        # Check official domains first
        if clean_domain in self.official_domains:
            return results

        # Check for brand impersonation
        for brand_name, variations in self.brand_patterns.items():
            brand_lower = brand_name.lower()
            weight = self.brand_weights.get(brand_name, 0.8)

            # Skip if brand name is too short
            if len(brand_lower) < 3:
                continue

            # Check character substitutions/variations
            for variation in variations:
                if variation in main_domain:
                    results['is_impersonation'] = True
                    results['impersonated_brand'] = brand_name
                    results['method'] = 'character_substitution'
                    results['confidence'] = weight * 0.9
                    results['detected_brands'].append(brand_name)
                    return results

            # Check if brand name is contained in domain
            if brand_lower in main_domain and brand_lower != main_domain:
                results['is_impersonation'] = True
                results['impersonated_brand'] = brand_name
                results['method'] = 'brand_contained'
                results['confidence'] = weight * 0.8
                results['detected_brands'].append(brand_name)
                return results

        return results

    def _extract_domain(self, url):
        """Extract domain from URL"""
        try:
            return urlparse(url).netloc
        except:
            return ''

    def analyze_enhanced(self, url, fetch_page=True):
        """
        Complete analysis with all layers - BALANCED thresholds
        """
        print(f"\n🔍 Analyzing: {url}")
        start_time = time.time()

        domain = self._extract_domain(url)
        clean_domain = self._clean_domain(domain)

        # STEP 0: Trusted domains whitelist (HIGHEST PRIORITY)
        if clean_domain in self.trusted_domains:
            print(f"   ✅ Trusted domain whitelist")
            return {
                'url': url,
                'domain': domain,
                'verdict': 'legitimate',
                'confidence': 0.99,
                'explanation': 'Trusted domain whitelist',
                'analysis_time_ms': int((time.time() - start_time) * 1000),
                'override_reason': 'whitelist'
            }

        # STEP 1: Official domain check
        if clean_domain in self.official_domains:
            brand = next((b for b in self.brand_db if b.lower() in clean_domain), 'Unknown')
            return {
                'url': url,
                'domain': domain,
                'verdict': 'legitimate',
                'confidence': 0.95,
                'explanation': f'Official domain of {brand}',
                'analysis_time_ms': int((time.time() - start_time) * 1000),
                'override_reason': 'official_domain'
            }

        # STEP 2: Brand impersonation analysis
        print("1️⃣ Brand analysis...")
        brand_analysis = self._analyze_brand_impersonation(url, domain)

        # STEP 3: Google Safe Browsing
        print("2️⃣ Google Safe Browsing...")
        google_result = self.api.check_google_safe_browsing(url)
        google_safe = google_result.get('safe', True)

        # STEP 4: AI model prediction
        print("3️⃣ Local AI model...")
        model_phishing = False
        model_prob = 0.1

        if self.ai_model:
            try:
                ai_result = self.ai_model.predict(url)
                model_phishing = ai_result['is_phishing']
                model_prob = ai_result['probability']
                print(f"   AI says: {'PHISHING' if model_phishing else 'LEGIT'} ({model_prob:.3f})")
            except Exception as e:
                print(f"   ⚠️ AI model error: {e}")

        # STEP 5: Page analysis (optional)
        page_analysis = None
        if fetch_page:
            print("4️⃣ Page analysis...")
            page_analysis = self.page_analyzer.analyze_page(url, brand_analysis.get('impersonated_brand'))
            if page_analysis:
                print(f"   Page score: {page_analysis.get('phishing_score', 0):.2f}")

        # ===== BALANCED DECISION LOGIC =====
        verdict = 'legitimate'
        confidence = 0.5
        explanation = 'All checks passed'
        override_reason = 'none'

        # LEVEL 1: GOOGLE SAFE BROWSING (highest authority)
        if not google_safe:
            verdict = 'phishing'
            confidence = 0.97
            explanation = 'Confirmed by Google Safe Browsing'
            override_reason = 'google_malicious'

        # LEVEL 2: CREDIT CARD/SSN DETECTION (very strong signal)
        elif page_analysis and page_analysis.get('sensitive_fields_found'):
            sensitive = page_analysis['sensitive_fields_found']
            if 'credit_card' in sensitive or 'ssn' in sensitive:
                verdict = 'phishing'
                confidence = 0.95
                explanation = f'Page requests sensitive data: {sensitive}'
                override_reason = 'sensitive_data'

        # LEVEL 3: STRONG BRAND IMPERSONATION (high confidence)
        elif brand_analysis['is_impersonation'] and brand_analysis['confidence'] > 0.85:
            verdict = 'phishing'
            confidence = brand_analysis['confidence']
            explanation = f"Impersonating {brand_analysis['impersonated_brand']}"
            override_reason = 'brand_impersonation_high'

        # LEVEL 4: PAGE ANALYSIS HIGH RISK
        elif page_analysis and page_analysis['phishing_score'] > 0.7:
            verdict = 'phishing'
            confidence = page_analysis['phishing_score']
            explanation = 'High-risk page content'
            override_reason = 'page_high_risk'

        # LEVEL 5: AI MODEL VERY CONFIDENT
        elif model_phishing and model_prob > 0.8:
            verdict = 'phishing'
            confidence = model_prob
            explanation = 'AI model highly confident'
            override_reason = 'ai_high_confidence'

        # LEVEL 6: BRAND IMPERSONATION (medium confidence)
        elif brand_analysis['is_impersonation']:
            verdict = 'suspicious'
            confidence = brand_analysis['confidence']
            explanation = f"Possible impersonation of {brand_analysis['impersonated_brand']}"
            override_reason = 'brand_impersonation_medium'

        # LEVEL 7: PAGE ANALYSIS MEDIUM RISK
        elif page_analysis and page_analysis['phishing_score'] > 0.4:
            verdict = 'suspicious'
            confidence = page_analysis['phishing_score']
            explanation = 'Suspicious page elements detected'
            override_reason = 'page_medium_risk'

        # LEVEL 8: AI MODEL MEDIUM CONFIDENCE
        elif model_phishing and model_prob > 0.5:
            verdict = 'suspicious'
            confidence = model_prob * 0.8  # Discount slightly
            explanation = 'AI model suspicious'
            override_reason = 'ai_medium_confidence'

        # LEVEL 9: EVERYTHING PASSED - LEGITIMATE
        else:
            verdict = 'legitimate'
            confidence = 1 - model_prob if model_prob > 0 else 0.95
            explanation = 'All checks passed'
            override_reason = 'all_checks_passed'

        # Prepare results
        results = {
            'url': url,
            'domain': domain,
            'verdict': verdict,
            'confidence': round(confidence, 3),
            'explanation': explanation,
            'override_reason': override_reason,
            'analysis_time_ms': int((time.time() - start_time) * 1000),
            'brand_analysis': brand_analysis,
            'google_safe': google_safe,
            'model_phishing_prob': round(model_prob, 3),
            'page_analysis': page_analysis
        }

        # Print summary
        self._print_results(results)
        return results

    def _print_results(self, results):
        """Print analysis results"""
        verdict = results['verdict']
        if verdict == 'phishing':
            icon = '🚨'
        elif verdict == 'suspicious':
            icon = '⚠️'
        else:
            icon = '✅'

        print(f"\n{icon} VERDICT: {verdict.upper()} ({results['confidence']:.1%})")
        print(f"📝 {results['explanation']}")

        if results['override_reason'] != 'none':
            print(f"🔧 Reason: {results['override_reason']}")

        print(f"⏱️  Time: {results['analysis_time_ms']}ms")

    def analyze_batch(self, urls, max_workers=10, fetch_page=True):
        """Analyze multiple URLs in parallel"""
        print(f"\n🚀 Batch analyzing {len(urls)} URLs with {max_workers} workers...")
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(self.analyze_enhanced, url, fetch_page): url
                for url in urls
            }

            completed = 0
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result(timeout=60)
                    results.append(result)
                    completed += 1
                    print(f"\r   Progress: {completed}/{len(urls)}", end="")
                except Exception as e:
                    print(f"\n❌ Failed: {url} - {e}")
                    results.append({'url': url, 'error': str(e), 'verdict': 'unknown'})

        # Summarize
        phishing = sum(1 for r in results if r.get('verdict') == 'phishing')
        legit = sum(1 for r in results if r.get('verdict') == 'legitimate')
        suspicious = sum(1 for r in results if r.get('verdict') == 'suspicious')
        failed = sum(1 for r in results if r.get('verdict') == 'unknown')

        print(f"\n\n📊 BATCH SUMMARY:")
        print(f"   Phishing: {phishing}")
        print(f"   Legitimate: {legit}")
        print(f"   Suspicious: {suspicious}")
        print(f"   Failed: {failed}")

        return results

    def analyze_with_fallback(self, url):
        """Try page analysis with fallback"""
        try:
            return self.analyze_enhanced(url, fetch_page=True)
        except Exception as e:
            print(f"⚠️ Page analysis failed, using URL-only: {e}")
            return self.analyze_enhanced(url, fetch_page=False)


# Example usage
if __name__ == "__main__":
    detector = EnhancedUltimatePhishingDetector()

    # Test single URLs
    test_urls = [
        "https://www.google.com",
        "https://www.facebook.com",
        "https://paypal.com.security-verify.com/login"
    ]

    for url in test_urls:
        result = detector.analyze_enhanced(url)
        print()