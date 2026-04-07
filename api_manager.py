"""
Unified API Manager for Google Safe Browsing and Whois API
with intelligent caching and usage optimization
"""
import requests
import time
import json
import hashlib
from datetime import datetime, timedelta
from urllib.parse import urlparse
from collections import OrderedDict
import os


class APIManager:
    """Manage all external API calls with smart caching"""

    def __init__(self, config_path='configs/api_keys.json'):
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = json.load(f)

        print(f"✅ Google API Limit: {self.config['usage_limits']['google_daily']:,} calls/day")
        print(f"✅ Whois API Limit: {self.config['usage_limits']['whois_daily']:,} calls/day")

        # Initialize cache
        self.cache = OrderedDict()
        self.cache_max_size = 50000  # Increased cache size

        # API usage tracking with 10K limit
        self.usage = {
            'google': {'today': 0, 'reset_time': time.time(), 'limit': self.config['usage_limits']['google_daily']},
            'whois': {'today': 0, 'reset_time': time.time(), 'limit': self.config['usage_limits']['whois_daily']}
        }

        # Batch optimization settings
        self.batch_enabled = self.config.get('batch_optimization', {}).get('enabled', True)
        self.batch_size = self.config.get('batch_optimization', {}).get('batch_size', 500)

        # Load cache from disk
        self._load_cache()

        print(f"✅ API Manager initialized. Cache: {len(self.cache):,} entries")

    def check_google_safe_browsing(self, url, force_fresh=False):
        """Check URL with Google Safe Browsing - OPTIMIZED FOR 10K LIMIT"""
        self._reset_daily_counters()

        cache_key = f"google_{hashlib.md5(url.encode()).hexdigest()[:12]}"

        # With 10K calls, we can afford to be less aggressive with caching
        # Check cache (but with shorter TTL since we can afford fresh checks)
        if not force_fresh:
            cached = self._get_cache(cache_key)
            if cached and time.time() - cached['timestamp'] < 43200:  # 12 hours instead of 24
                cached['cache_hit'] = True
                return cached

        # With 10K limit, we have PLENTY of calls
        # Only warn at 90% usage instead of 95%
        if self.usage['google']['today'] >= self.usage['google']['limit'] * 0.9:
            print(f"⚠️ Google API usage at 90% ({self.usage['google']['today']}/{self.usage['google']['limit']})")
            return cached or {'safe': True, 'error': 'api_limit', 'cache_hit': False}

        # Make API call (we can afford to be less conservative)
        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            response = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={'key': self.config['google_safe_browsing']},
                json=payload,
                timeout=2  # Shorter timeout since we can retry
            )

            self.usage['google']['today'] += 1

            if response.status_code == 200:
                data = response.json()
                result = self._parse_google_response(data, url)
            else:
                print(f"Google API error {response.status_code}: {response.text[:100]}")
                result = {'safe': True, 'error': f'http_{response.status_code}', 'cache_hit': False}

        except requests.exceptions.Timeout:
            # With 10K calls, we can afford to retry once
            print(f"Google API timeout, retrying...")
            time.sleep(0.5)
            return self.check_google_safe_browsing(url, force_fresh=True)

        except Exception as e:
            result = {'safe': True, 'error': str(e), 'cache_hit': False}

        # Cache result with shorter TTL (12 hours)
        result['timestamp'] = time.time()
        self._set_cache(cache_key, result)
        result['cache_hit'] = False

        # Only save cache every 1000 entries to reduce disk I/O
        if len(self.cache) % 1000 == 0:
            self.save_cache()

        return result

    def get_whois_info(self, domain):
        """Get Whois information for domain"""
        self._reset_daily_counters()

        cache_key = f"whois_{domain}"

        # Check cache
        cached = self._get_cache(cache_key)
        if cached and time.time() - cached['timestamp'] < 2592000:  # 30 days
            cached['cache_hit'] = True
            return cached

        # Check API limit
        if self.usage['whois']['today'] >= self.config['usage_limits']['whois_daily'] * 0.9:
            print("⚠️ Whois API limit near, using cache")
            return cached or {'error': 'api_limit', 'cache_hit': False}

        # Make API call
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

        # Cache result
        result['timestamp'] = time.time()
        self._set_cache(cache_key, result)
        result['cache_hit'] = False

        return result

    def _parse_google_response(self, data, url):
        """Parse Google Safe Browsing response"""
        if 'matches' in data:
            threats = [match['threatType'] for match in data['matches']]
            return {
                'safe': False,
                'threats': threats,
                'confidence': 0.95
            }

        return {'safe': True, 'threats': [], 'confidence': 0.85}

    def _parse_whois_response(self, data, domain):
        """Parse Whois API response"""
        try:
            record = data.get('WhoisRecord', {})
            created = record.get('createdDate', '')

            # Calculate domain age
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

    def _get_cache(self, key):
        """Get item from cache"""
        if key in self.cache:
            item = self.cache[key]
            # Move to end (most recently used)
            self.cache.move_to_end(key)
            return item
        return None

    def _set_cache(self, key, value):
        """Set item in cache with LRU eviction"""
        if len(self.cache) >= self.cache_max_size:
            # Remove oldest item
            self.cache.popitem(last=False)

        self.cache[key] = value

    def _reset_daily_counters(self):
        """Reset daily counters if new day"""
        now = time.time()
        if now - self.usage['google']['reset_time'] > 86400:
            self.usage['google'] = {'today': 0, 'reset_time': now}
        if now - self.usage['whois']['reset_time'] > 86400:
            self.usage['whois'] = {'today': 0, 'reset_time': now}

    def _load_cache(self):
        """Load cache from disk"""
        cache_file = 'data/api_cache.json'
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    cache_data = json.load(f)
                    self.cache = OrderedDict(cache_data)
                print(f"📂 Loaded cache from {cache_file}")
            except:
                print("⚠️ Could not load cache file")

    def save_cache(self):
        """Save cache to disk"""
        cache_file = 'data/api_cache.json'
        try:
            with open(cache_file, 'w') as f:
                # Convert OrderedDict to regular dict for JSON serialization
                json.dump(dict(self.cache), f)
            print(f"💾 Cache saved to {cache_file}")
        except Exception as e:
            print(f"❌ Failed to save cache: {e}")

    def get_stats(self):
        """Get API usage statistics"""
        return {
            'cache_size': len(self.cache),
            'google_used_today': self.usage['google']['today'],
            'google_remaining': self.config['usage_limits']['google_daily'] - self.usage['google']['today'],
            'whois_used_today': self.usage['whois']['today'],
            'whois_remaining': self.config['usage_limits']['whois_daily'] - self.usage['whois']['today']
        }

    # Add this method to your APIManager class in api_manager.py

    def check_multiple_urls_batch(self, urls):
        """Check multiple URLs in a single Google API call"""

        # Filter out URLs that are already in cache
        urls_to_check = []
        cached_results = {}

        for url in urls:
            cache_key = f"google_{hashlib.md5(url.encode()).hexdigest()[:12]}"
            cached = self._get_cache(cache_key)

            if cached and time.time() - cached['timestamp'] < 86400:
                cached['cache_hit'] = True
                cached_results[url] = cached
            else:
                urls_to_check.append(url)

        # If all URLs are cached, return immediately
        if not urls_to_check:
            return cached_results

        # Check API limit for batch
        batch_size = len(urls_to_check)
        if self.usage['google']['today'] + batch_size > self.config['usage_limits']['google_daily'] * 0.95:
            print(f"⚠️ Not enough API calls for batch of {batch_size}, checking individually")
            return self._check_urls_individually(urls_to_check, cached_results)

        # Prepare batch request (Google allows up to 500 URLs per call)
        request_body = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url} for url in urls_to_check]
            }
        }

        try:
            response = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={'key': self.config['google_safe_browsing']},
                json=request_body,
                timeout=5
            )

            self.usage['google']['today'] += 1  # Only 1 API call for the batch!

            if response.status_code == 200:
                batch_results = self._parse_google_batch_response(response.json(), urls_to_check)

                # Update cache and combine results
                for url, result in batch_results.items():
                    cache_key = f"google_{hashlib.md5(url.encode()).hexdigest()[:12]}"
                    result['timestamp'] = time.time()
                    self._set_cache(cache_key, result)
                    result['cache_hit'] = False

                # Combine cached and fresh results
                batch_results.update(cached_results)
                return batch_results

        except Exception as e:
            print(f"Batch Google API failed: {e}")

        # Fallback to individual checks
        return self._check_urls_individually(urls_to_check, cached_results)

    def _parse_google_batch_response(self, data, original_urls):
        """Parse batch Google API response"""
        results = {}

        # Initialize all as safe
        for url in original_urls:
            results[url] = {'safe': True, 'threats': []}

        # Mark unsafe ones
        if 'matches' in data:
            for match in data['matches']:
                url = match['threat']['url']
                if url in results:
                    results[url]['safe'] = False
                    results[url]['threats'].append(match['threatType'])

        return results

    def _check_urls_individually(self, urls, cached_results):
        """Fallback: check URLs one by one"""
        for url in urls:
            result = self.check_google_safe_browsing(url)
            cached_results[url] = result

        return cached_results

    def check_multiple_urls_aggressive(self, urls):
        """Aggressive batch checking with 10K limit"""

        # With 10K calls, we can check EVERYTHING
        print(f"🔍 Aggressive batch checking {len(urls)} URLs")

        # Separate into cached and fresh
        fresh_urls = []
        all_results = {}

        for url in urls:
            cache_key = f"google_{hashlib.md5(url.encode()).hexdigest()[:12]}"
            cached = self._get_cache(cache_key)

            # With 10K limit, use shorter cache TTL (6 hours)
            if cached and time.time() - cached['timestamp'] < 21600:  # 6 hours
                cached['cache_hit'] = True
                all_results[url] = cached
            else:
                fresh_urls.append(url)

        print(f"   {len(urls) - len(fresh_urls)} cached, {len(fresh_urls)} need fresh check")

        # Process fresh URLs in large batches
        if fresh_urls:
            # Google allows 500 URLs per batch, we can use multiple batches
            batch_count = (len(fresh_urls) + self.batch_size - 1) // self.batch_size

            for batch_num in range(batch_count):
                start_idx = batch_num * self.batch_size
                end_idx = min((batch_num + 1) * self.batch_size, len(fresh_urls))
                batch_urls = fresh_urls[start_idx:end_idx]

                print(f"   Processing batch {batch_num + 1}/{batch_count} ({len(batch_urls)} URLs)")

                batch_result = self._process_batch(batch_urls)
                all_results.update(batch_result)

                # Small delay between batches
                if batch_num < batch_count - 1:
                    time.sleep(0.1)

        return all_results

    def _process_batch(self, urls):
        """Process a batch of URLs"""
        request_body = {
            "client": {"clientId": "phishing-detector", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url} for url in urls]
            }
        }

        try:
            response = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={'key': self.config['google_safe_browsing']},
                json=request_body,
                timeout=5
            )

            self.usage['google']['today'] += 1  # Only 1 call for entire batch!

            if response.status_code == 200:
                return self._parse_batch_response(response.json(), urls)
            else:
                print(f"Batch API error: {response.status_code}")

        except Exception as e:
            print(f"Batch processing failed: {e}")

        # Fallback: check individually
        return self._check_urls_individually_fast(urls)

    def _check_urls_individually_fast(self, urls):
        """Fast individual checking with concurrent requests"""
        import concurrent.futures

        results = {}

        # With 10K limit, we can use threading for speed
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {executor.submit(self.check_google_safe_browsing, url): url for url in urls}

            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    results[url] = future.result(timeout=3)
                except Exception as e:
                    results[url] = {'safe': True, 'error': str(e), 'cache_hit': False}

        return results