"""
Unified API Manager for Google Safe Browsing and Whois API
with intelligent caching and usage optimization.
"""
import requests
import time
import json
import hashlib
from datetime import datetime
from collections import OrderedDict
import os
from concurrent.futures import ThreadPoolExecutor, as_completed


class APIManager:
    """Manage external API calls with caching and rate limit awareness."""

    def __init__(self, config_path=None):
        # Load configuration – if no path given, look for environment variables
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        else:
            # Fallback to environment variables (recommended for production)
            self.config = {
                'google_safe_browsing': os.environ.get('GOOGLE_SAFE_BROWSING_KEY', ''),
                'whois_api': os.environ.get('WHOIS_API_KEY', ''),
                'usage_limits': {
                    'google_daily': 10000,
                    'whois_daily': 500
                },
                'batch_optimization': {
                    'enabled': True,
                    'batch_size': 500
                }
            }

        # Initialize cache
        self.cache = OrderedDict()
        self.cache_max_size = 50000

        # API usage tracking
        self.usage = {
            'google': {
                'today': 0,
                'reset_time': time.time(),
                'limit': self.config['usage_limits']['google_daily']
            },
            'whois': {
                'today': 0,
                'reset_time': time.time(),
                'limit': self.config['usage_limits']['whois_daily']
            }
        }

        # Batch settings
        self.batch_enabled = self.config.get('batch_optimization', {}).get('enabled', True)
        self.batch_size = self.config.get('batch_optimization', {}).get('batch_size', 500)

        # Load cache from disk if available
        self._load_cache()

    def check_google_safe_browsing(self, url, force_fresh=False):
        """Check a single URL with Google Safe Browsing."""
        self._reset_daily_counters()

        cache_key = f"google_{hashlib.md5(url.encode()).hexdigest()[:12]}"

        if not force_fresh:
            cached = self._get_cache(cache_key)
            if cached and time.time() - cached['timestamp'] < 43200:  # 12 hours
                cached['cache_hit'] = True
                return cached

        # Check rate limit (warn at 90%)
        if self.usage['google']['today'] >= self.usage['google']['limit'] * 0.9:
            return cached or {'safe': True, 'error': 'api_limit', 'cache_hit': False}

        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            response = requests.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={'key': self.config['google_safe_browsing']},
                json=payload,
                timeout=2
            )

            self.usage['google']['today'] += 1

            if response.status_code == 200:
                result = self._parse_google_response(response.json(), url)
            else:
                result = {'safe': True, 'error': f'http_{response.status_code}', 'cache_hit': False}

        except requests.exceptions.Timeout:
            # Retry once on timeout
            time.sleep(0.5)
            return self.check_google_safe_browsing(url, force_fresh=True)

        except Exception as e:
            result = {'safe': True, 'error': str(e), 'cache_hit': False}

        result['timestamp'] = time.time()
        self._set_cache(cache_key, result)
        result['cache_hit'] = False

        # Persist cache periodically
        if len(self.cache) % 1000 == 0:
            self.save_cache()

        return result

    def check_multiple_urls(self, urls):
        """Check multiple URLs in batch using a single Google API call."""
        self._reset_daily_counters()

        # Separate cached and fresh URLs
        urls_to_check = []
        results = {}

        for url in urls:
            cache_key = f"google_{hashlib.md5(url.encode()).hexdigest()[:12]}"
            cached = self._get_cache(cache_key)
            if cached and time.time() - cached['timestamp'] < 43200:
                cached['cache_hit'] = True
                results[url] = cached
            else:
                urls_to_check.append(url)

        if not urls_to_check:
            return results

        # Check rate limit for the batch
        if self.usage['google']['today'] + len(urls_to_check) > self.usage['google']['limit'] * 0.95:
            # Fallback to individual checks
            return self._check_urls_individually(urls_to_check, results)

        request_body = {
            "client": {"clientId": "phishing-detector", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url} for url in urls_to_check]
            }
        }

        try:
            response = requests.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={'key': self.config['google_safe_browsing']},
                json=request_body,
                timeout=5
            )

            self.usage['google']['today'] += 1

            if response.status_code == 200:
                batch_results = self._parse_google_batch_response(response.json(), urls_to_check)
                for url, result in batch_results.items():
                    cache_key = f"google_{hashlib.md5(url.encode()).hexdigest()[:12]}"
                    result['timestamp'] = time.time()
                    self._set_cache(cache_key, result)
                    result['cache_hit'] = False
                    results[url] = result
                return results

        except Exception as e:
            print(f"Batch API failed: {e}")

        # Fallback
        return self._check_urls_individually(urls_to_check, results)

    def get_whois_info(self, domain):
        """Retrieve WHOIS information for a domain."""
        self._reset_daily_counters()

        cache_key = f"whois_{domain}"
        cached = self._get_cache(cache_key)
        if cached and time.time() - cached['timestamp'] < 2592000:  # 30 days
            cached['cache_hit'] = True
            return cached

        if self.usage['whois']['today'] >= self.usage['whois']['limit'] * 0.9:
            return cached or {'error': 'api_limit', 'cache_hit': False}

        try:
            response = requests.get(
                "https://www.whoisxmlapi.com/whoisserver/WhoisService",
                params={
                    'apiKey': self.config['whois_api'],
                    'domainName': domain,
                    'outputFormat': 'JSON',
                    'da': 1
                },
                timeout=5
            )

            self.usage['whois']['today'] += 1

            if response.status_code == 200:
                result = self._parse_whois_response(response.json(), domain)
            else:
                result = {'error': f'http_{response.status_code}', 'cache_hit': False}

        except Exception as e:
            result = {'error': str(e), 'cache_hit': False}

        result['timestamp'] = time.time()
        self._set_cache(cache_key, result)
        result['cache_hit'] = False
        return result

    def _parse_google_response(self, data, url):
        """Parse a single‑URL Google Safe Browsing response."""
        if 'matches' in data:
            threats = [match['threatType'] for match in data['matches']]
            return {'safe': False, 'threats': threats, 'confidence': 0.95}
        return {'safe': True, 'threats': [], 'confidence': 0.85}

    def _parse_google_batch_response(self, data, original_urls):
        """Parse a batch Google Safe Browsing response."""
        results = {url: {'safe': True, 'threats': []} for url in original_urls}
        if 'matches' in data:
            for match in data['matches']:
                url = match['threat']['url']
                if url in results:
                    results[url]['safe'] = False
                    results[url]['threats'].append(match['threatType'])
        return results

    def _parse_whois_response(self, data, domain):
        """Parse the WHOIS API response."""
        try:
            record = data.get('WhoisRecord', {})
            created = record.get('createdDate', '')
            age_days = 0
            if created:
                created_date = datetime.strptime(created.split('T')[0], '%Y-%m-%d')
                age_days = (datetime.now() - created_date).days

            return {
                'domain': domain,
                'created_date': created,
                'age_days': age_days,
                'registrar': record.get('registrarName', ''),
                'expires_date': record.get('expiresDate', ''),
                'updated_date': record.get('updatedDate', ''),
                'success': True
            }
        except Exception as e:
            return {'domain': domain, 'error': str(e), 'success': False}

    def _check_urls_individually(self, urls, existing_results):
        """Fallback: check URLs one by one using threading."""
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.check_google_safe_browsing, url): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    existing_results[url] = future.result(timeout=3)
                except Exception:
                    existing_results[url] = {'safe': True, 'error': 'thread_timeout'}
        return existing_results

    def _get_cache(self, key):
        """Retrieve an item from the LRU cache."""
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key]
        return None

    def _set_cache(self, key, value):
        """Store an item in the LRU cache."""
        if len(self.cache) >= self.cache_max_size:
            self.cache.popitem(last=False)
        self.cache[key] = value

    def _reset_daily_counters(self):
        """Reset daily API counters at midnight."""
        now = time.time()
        if now - self.usage['google']['reset_time'] > 86400:
            self.usage['google'] = {'today': 0, 'reset_time': now, 'limit': self.config['usage_limits']['google_daily']}
        if now - self.usage['whois']['reset_time'] > 86400:
            self.usage['whois'] = {'today': 0, 'reset_time': now, 'limit': self.config['usage_limits']['whois_daily']}

    def _load_cache(self):
        """Load cache from disk (if available)."""
        cache_file = 'data/api_cache.json'
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    self.cache = OrderedDict(json.load(f))
            except (json.JSONDecodeError, IOError):
                pass

    def save_cache(self):
        """Persist cache to disk."""
        cache_file = 'data/api_cache.json'
        try:
            os.makedirs(os.path.dirname(cache_file), exist_ok=True)
            with open(cache_file, 'w') as f:
                json.dump(dict(self.cache), f)
        except Exception:
            pass  # Non‑critical, do not crash

    def get_stats(self):
        """Return current API usage statistics."""
        return {
            'cache_size': len(self.cache),
            'google_used_today': self.usage['google']['today'],
            'google_remaining': self.config['usage_limits']['google_daily'] - self.usage['google']['today'],
            'whois_used_today': self.usage['whois']['today'],
            'whois_remaining': self.config['usage_limits']['whois_daily'] - self.usage['whois']['today']
        }
