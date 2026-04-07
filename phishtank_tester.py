"""
Enhanced PhishTank Testing Suite - Test MORE phishing links with better analysis
"""
import requests
import json
import csv
import time
import os
import gzip
import io
from datetime import datetime, timedelta
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import pandas as pd


class EnhancedPhishTankTester:
    """
    Enhanced PhishTank testing with parallel processing and better analysis
    """

    def __init__(self, detector, max_workers=5):
        self.detector = detector
        self.max_workers = max_workers

        # Public database URLs
        self.database_urls = {
            'json': 'http://data.phishtank.com/data/online-valid.json',
            'json_gz': 'http://data.phishtank.com/data/online-valid.json.gz',
            'json_bz2': 'http://data.phishtank.com/data/online-valid.json.bz2',
        }

        # Statistics
        self.results = {
            'true_positives': 0,
            'false_negatives': 0,
            'true_negatives': 0,
            'false_positives': 0,
            'by_brand': defaultdict(lambda: {'tp': 0, 'fn': 0, 'total': 0}),
            'by_tld': defaultdict(lambda: {'tp': 0, 'fn': 0, 'total': 0}),
            'by_method': defaultdict(int),
            'detailed': [],
            'test_timestamp': datetime.now().isoformat()
        }

    def download_large_dataset(self, limit=5000, target_brand=None):
        """
        Download LARGE phishing dataset (up to 5000+ URLs)
        """
        print(f"📥 Downloading LARGE PhishTank dataset...")

        # Try different formats if one fails
        urls_to_try = [
            self.database_urls['json_gz'],
            self.database_urls['json'],
            self.database_urls['json_bz2']
        ]

        headers = {
            'User-Agent': 'PhishingDetector/2.0 (research/benchmarking)'
        }

        for data_url in urls_to_try:
            try:
                print(f"   Trying: {data_url}")
                response = requests.get(data_url, headers=headers, timeout=60)
                response.raise_for_status()

                # Handle compression
                if data_url.endswith('.gz'):
                    content = self._decompress_gzip(response.content)
                elif data_url.endswith('.bz2'):
                    content = self._decompress_bz2(response.content)
                else:
                    content = response.content

                # Parse JSON
                all_phishing = json.loads(content)
                print(f"✅ Downloaded {len(all_phishing)} total phishing URLs")

                # Filter by target brand if specified
                if target_brand:
                    filtered = [
                        entry for entry in all_phishing
                        if entry.get('target', '').lower() == target_brand.lower()
                    ]
                    print(f"   Filtered to {len(filtered)} URLs targeting {target_brand}")
                    all_phishing = filtered

                # Apply limit and return
                return all_phishing[:limit]

            except Exception as e:
                print(f"   ❌ Failed: {e}")
                continue

        print("❌ All download attempts failed")
        return []

    def _decompress_gzip(self, compressed_data):
        """Decompress gzipped data"""
        import gzip
        buf = io.BytesIO(compressed_data)
        with gzip.GzipFile(fileobj=buf) as f:
            return f.read()

    def _decompress_bz2(self, compressed_data):
        """Decompress bz2 data"""
        import bz2
        return bz2.decompress(compressed_data)

    def get_extended_legitimate_set(self, count=1000):
        """
        Get LARGER set of legitimate URLs from multiple sources
        """
        legit_urls = []

        # Source 1: Alexa/Tranco top sites (simulated)
        top_domains = [
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
            'twitter.com', 'instagram.com', 'linkedin.com', 'netflix.com',
            'microsoft.com', 'apple.com', 'wikipedia.org', 'reddit.com',
            'ebay.com', 'zoom.us', 'office.com', 'live.com', 'bing.com',
            'cloudflare.com', 'github.com', 'stackoverflow.com', 'medium.com',
            'nytimes.com', 'bbc.com', 'cnn.com', 'weather.com', 'imdb.com',
            'whatsapp.com', 'spotify.com', 'telegram.org', 'dropbox.com'
        ]

        # Add main domains
        for domain in top_domains[:count//3]:
            legit_urls.append({
                'url': f"https://{domain}",
                'source': 'top_domain',
                'category': 'legitimate'
            })

        # Add subpages
        subpages = [
            '/login', '/signin', '/account', '/profile', '/settings',
            '/help', '/support', '/contact', '/about', '/terms',
            '/privacy', '/security', '/verify', '/confirm'
        ]

        for domain in top_domains[:count//3]:
            for page in subpages[:3]:  # Limit per domain
                legit_urls.append({
                    'url': f"https://{domain}{page}",
                    'source': 'subpage',
                    'category': 'legitimate'
                })

        # Add your detector's trusted domains
        for domain in list(self.detector._load_trusted_domains())[:count//3]:
            legit_urls.append({
                'url': f"https://{domain}",
                'source': 'trusted_domains',
                'category': 'legitimate'
            })


        # Shuffle and return
        import random
        random.shuffle(legit_urls)
        return legit_urls[:count]

    def test_url_batch(self, url_batch, url_type='phishing', target_brand='Other'):
        """
        Test a batch of URLs in parallel
        """
        batch_results = []

        for url_info in url_batch:
            url = url_info['url'] if isinstance(url_info, dict) else url_info
            target = url_info.get('target', target_brand) if isinstance(url_info, dict) else target_brand

            try:
                # Run detector
                result = self.detector.analyze_enhanced(url, fetch_page=True)

                # Determine if detected
                is_detected = result['verdict'] in ['phishing', 'suspicious']

                # Extract TLD for analysis
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
                tld = domain.split('.')[-1] if '.' in domain else 'unknown'

                batch_results.append({
                    'url': url,
                    'type': url_type,
                    'target': target,
                    'detected': is_detected,
                    'verdict': result['verdict'],
                    'confidence': result['confidence'],
                    'explanation': result['explanation'],
                    'override_reason': result.get('override_reason', 'none'),
                    'google_safe': result.get('google_safe', True),
                    'model_prob': result.get('model_phishing_prob', 0),
                    'domain': domain,
                    'tld': tld
                })

            except Exception as e:
                print(f"⚠️ Error testing {url}: {e}")
                batch_results.append({
                    'url': url,
                    'type': url_type,
                    'target': target,
                    'detected': False,
                    'error': str(e)
                })

        return batch_results

    def run_large_scale_test(self, phishing_limit=1000, legit_limit=500):
        """
        Run LARGE SCALE test with thousands of URLs
        """
        print("\n" + "="*70)
        print("🚀 ENHANCED LARGE-SCALE PHISHTANK TEST")
        print("="*70)

        # Download phishing dataset
        print("\n📊 PHASE 1: Downloading phishing URLs...")
        phishing_samples = self.download_large_dataset(limit=phishing_limit)

        if not phishing_samples:
            print("❌ Failed to download phishing data")
            return None

        # Get legitimate URLs
        print("\n📊 PHASE 2: Preparing legitimate URLs...")
        legitimate_samples = self.get_extended_legitimate_set(count=legit_limit)

        print(f"\n📈 TEST SUMMARY:")
        print(f"   - Phishing URLs: {len(phishing_samples)}")
        print(f"   - Legitimate URLs: {len(legitimate_samples)}")
        print(f"   - Total URLs: {len(phishing_samples) + len(legitimate_samples)}")
        print(f"   - Parallel workers: {self.max_workers}")

        # Split into batches for parallel processing
        phishing_batches = self._split_into_batches(phishing_samples, self.max_workers * 2)
        legit_batches = self._split_into_batches(legitimate_samples, self.max_workers)

        # Test phishing URLs in parallel
        print("\n🔴 PHASE 3: Testing PHISHING URLs...")
        phishing_results = self._run_parallel_tests(phishing_batches, 'phishing')

        # Test legitimate URLs in parallel
        print("\n🟢 PHASE 4: Testing LEGITIMATE URLs...")
        legit_results = self._run_parallel_tests(legit_batches, 'legitimate')

        # Combine and analyze results
        all_results = phishing_results + legit_results
        self._analyze_results(all_results)

        # Save detailed results
        self._save_results(all_results)

        # Generate visualizations
        self._generate_visualizations()

        return self.results

    def _split_into_batches(self, items, num_batches):
        """Split list into batches"""
        batch_size = max(1, len(items) // num_batches)
        return [items[i:i + batch_size] for i in range(0, len(items), batch_size)]

    def _run_parallel_tests(self, batches, url_type):
        """Run tests in parallel using ThreadPoolExecutor"""
        all_results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all batches
            futures = []
            for batch in batches:
                future = executor.submit(self.test_url_batch, batch, url_type)
                futures.append(future)

            # Process results with progress bar
            with tqdm(total=len(batches), desc=f"Testing {url_type} URLs") as pbar:
                for future in as_completed(futures):
                    batch_results = future.result()
                    all_results.extend(batch_results)
                    pbar.update(1)

        return all_results

    def _analyze_results(self, all_results):
        """Comprehensive analysis of test results"""

        # Reset results
        self.results = {
            'true_positives': 0,
            'false_negatives': 0,
            'true_negatives': 0,
            'false_positives': 0,
            'by_brand': defaultdict(lambda: {'tp': 0, 'fn': 0, 'total': 0}),
            'by_tld': defaultdict(lambda: {'tp': 0, 'fn': 0, 'total': 0}),
            'by_method': defaultdict(int),
            'detailed': all_results,
            'test_timestamp': datetime.now().isoformat()
        }

        # Analyze each result
        for r in all_results:
            if r['type'] == 'phishing':
                if r['detected']:
                    self.results['true_positives'] += 1
                else:
                    self.results['false_negatives'] += 1

                # Brand analysis
                brand = r.get('target', 'Other')
                self.results['by_brand'][brand]['total'] += 1
                if r['detected']:
                    self.results['by_brand'][brand]['tp'] += 1
                else:
                    self.results['by_brand'][brand]['fn'] += 1

                # TLD analysis
                tld = r.get('tld', 'unknown')
                self.results['by_tld'][tld]['total'] += 1
                if r['detected']:
                    self.results['by_tld'][tld]['tp'] += 1

                # Detection method
                method = r.get('override_reason', 'ai_model')
                self.results['by_method'][method] += 1

            else:  # legitimate
                if r['detected']:
                    self.results['false_positives'] += 1
                else:
                    self.results['true_negatives'] += 1

        # Print analysis
        self._print_enhanced_results()

    def _print_enhanced_results(self):
        """Print comprehensive analysis"""
        tp = self.results['true_positives']
        fn = self.results['false_negatives']
        tn = self.results['true_negatives']
        fp = self.results['false_positives']

        total_phishing = tp + fn
        total_legit = tn + fp
        total_all = total_phishing + total_legit

        print("\n" + "="*70)
        print("📊 ENHANCED TEST RESULTS")
        print("="*70)

        print(f"\n📈 OVERALL STATISTICS:")
        print(f"   Total URLs Tested: {total_all}")
        print(f"   Phishing URLs: {total_phishing}")
        print(f"   Legitimate URLs: {total_legit}")

        print(f"\n🎯 DETECTION PERFORMANCE:")
        print(f"   True Positives:  {tp:4d} ({tp/total_phishing*100:5.2f}%)")
        print(f"   False Negatives: {fn:4d} ({fn/total_phishing*100:5.2f}%)")
        print(f"   True Negatives:  {tn:4d} ({tn/total_legit*100:5.2f}%)")
        print(f"   False Positives: {fp:4d} ({fp/total_legit*100:5.2f}%)")

        # Calculate metrics
        accuracy = (tp + tn) / total_all
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        print(f"\n📈 KEY METRICS:")
        print(f"   Accuracy:  {accuracy*100:5.2f}%")
        print(f"   Precision: {precision*100:5.2f}%")
        print(f"   Recall:    {recall*100:5.2f}%")
        print(f"   F1-Score:  {f1*100:5.2f}%")

        # Detection methods breakdown
        print(f"\n🔍 DETECTION METHODS:")
        total_detected = tp
        for method, count in sorted(self.results['by_method'].items(), key=lambda x: x[1], reverse=True):
            pct = count / total_detected * 100 if total_detected > 0 else 0
            print(f"   {method:30s}: {count:4d} ({pct:5.2f}%)")

        # Brand performance
        if self.results['by_brand']:
            print(f"\n🏷️  TOP BRANDS PERFORMANCE:")
            brand_items = sorted(self.results['by_brand'].items(),
                               key=lambda x: x[1]['total'], reverse=True)[:10]
            for brand, counts in brand_items:
                if brand and brand != 'Other' and counts['total'] >= 5:
                    rate = counts['tp'] / counts['total'] * 100
                    print(f"   {brand:20s}: {counts['tp']:3d}/{counts['total']:3d} ({rate:5.2f}%)")

        # TLD analysis
        if self.results['by_tld']:
            print(f"\n🌐 TOP TLDs PERFORMANCE:")
            tld_items = sorted(self.results['by_tld'].items(),
                             key=lambda x: x[1]['total'], reverse=True)[:10]
            for tld, counts in tld_items:
                if tld not in ['com', 'org', 'net', 'unknown'] or counts['total'] < 5:
                    continue
                rate = counts['tp'] / counts['total'] * 100
                print(f"   .{tld:8s}: {counts['tp']:3d}/{counts['total']:3d} ({rate:5.2f}%)")

    def _save_results(self, all_results):
        """Save detailed results to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save as CSV
        csv_file = f'phishtank_test_results_{timestamp}.csv'
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            if all_results:
                writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
                writer.writeheader()
                writer.writerows(all_results)
        print(f"\n💾 Results saved to: {csv_file}")

        # Save as JSON
        json_file = f'phishtank_test_results_{timestamp}.json'
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2)
        print(f"💾 Detailed stats saved to: {json_file}")

        # Save missed URLs for analysis
        missed_file = f'missed_phishing_{timestamp}.txt'
        with open(missed_file, 'w') as f:
            f.write("MISSED PHISHING URLS:\n")
            f.write("="*50 + "\n")
            for r in all_results:
                if r['type'] == 'phishing' and not r['detected']:
                    f.write(f"URL: {r['url']}\n")
                    f.write(f"Target: {r.get('target', 'Unknown')}\n")
                    f.write(f"Confidence: {r.get('confidence', 0)}\n")
                    f.write(f"Explanation: {r.get('explanation', 'N/A')}\n")
                    f.write("-"*50 + "\n")
        print(f"💾 Missed URLs saved to: {missed_file}")

    def _generate_visualizations(self):
        """Generate performance visualizations"""
        try:
            import matplotlib.pyplot as plt

            # Create figure with subplots
            fig, axes = plt.subplots(2, 2, figsize=(15, 12))

            # 1. Confusion Matrix
            ax1 = axes[0, 0]
            tp = self.results['true_positives']
            fn = self.results['false_negatives']
            tn = self.results['true_negatives']
            fp = self.results['false_positives']

            matrix = [[tn, fp], [fn, tp]]
            im = ax1.imshow(matrix, cmap='Blues')
            ax1.set_xticks([0, 1])
            ax1.set_yticks([0, 1])
            ax1.set_xticklabels(['Predicted Legit', 'Predicted Phish'])
            ax1.set_yticklabels(['Actual Legit', 'Actual Phish'])
            ax1.set_title('Confusion Matrix')

            for i in range(2):
                for j in range(2):
                    text = ax1.text(j, i, matrix[i][j],
                                   ha="center", va="center", color="black", fontsize=14)

            # 2. Detection Methods Pie Chart
            ax2 = axes[0, 1]
            methods = self.results['by_method']
            if methods:
                labels = list(methods.keys())
                sizes = list(methods.values())
                ax2.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
                ax2.set_title('Detection Methods')

            # 3. Brand Performance Bar Chart
            ax3 = axes[1, 0]
            brands = []
            rates = []
            for brand, counts in sorted(self.results['by_brand'].items(),
                                       key=lambda x: x[1]['total'], reverse=True)[:8]:
                if brand != 'Other' and counts['total'] >= 5:
                    brands.append(brand[:15])  # Truncate long names
                    rates.append(counts['tp'] / counts['total'] * 100)

            if brands:
                ax3.barh(brands, rates, color='green')
                ax3.set_xlabel('Detection Rate (%)')
                ax3.set_title('Detection Rate by Brand')
                ax3.set_xlim(0, 100)

            # 4. TLD Performance
            ax4 = axes[1, 1]
            tlds = []
            tld_rates = []
            for tld, counts in sorted(self.results['by_tld'].items(),
                                     key=lambda x: x[1]['total'], reverse=True)[:8]:
                if tld not in ['unknown'] and counts['total'] >= 5:
                    tlds.append(f".{tld}")
                    tld_rates.append(counts['tp'] / counts['total'] * 100)

            if tlds:
                ax4.bar(tlds, tld_rates, color='orange')
                ax4.set_ylabel('Detection Rate (%)')
                ax4.set_title('Detection Rate by TLD')
                ax4.set_ylim(0, 100)
                plt.setp(ax4.get_xticklabels(), rotation=45, ha='right')

            plt.tight_layout()

            # Save figure
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            plt.savefig(f'phishtank_analysis_{timestamp}.png', dpi=300, bbox_inches='tight')
            print(f"📊 Visualization saved to: phishtank_analysis_{timestamp}.png")

        except Exception as e:
            print(f"⚠️ Could not generate visualizations: {e}")


# Usage example
if __name__ == "__main__":
    from src.ultimate_detector import EnhancedUltimatePhishingDetector

    # Initialize detector
    detector = EnhancedUltimatePhishingDetector()

    # Initialize enhanced tester
    tester = EnhancedPhishTankTester(detector, max_workers=10)  # More parallel workers!

    # Run LARGE scale test
    results = tester.run_large_scale_test(
        phishing_limit=2000,  # Test 2000 phishing URLs
        legit_limit=1000       # Test 1000 legitimate URLs
    )

    # Print summary
    if results:
        print("\n✅ LARGE SCALE TEST COMPLETE!")
        print(f"   True Positives: {results['true_positives']}")
        print(f"   False Negatives: {results['false_negatives']}")
        print(f"   Accuracy: {results['true_positives']/(results['true_positives']+results['false_negatives'])*100:.2f}%")