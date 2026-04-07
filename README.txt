# ScamScanBeta_FYP
A phishing Detection Model that receives URL input and gives confidence level of whether it is phishing or legitimate. Verified using PhishTank online valid fresh URLs in 2026 March and 2026 April, accuracy from 96.15 - 97.85% 
================================================================================
                            SCAMSCAN BETA
                  Multi‑Modal Transformer for Real‑World
                         Phishing Detection
================================================================================

Authors: ChanPakYuMarco
Affiliation: City University of Hong Kong
Contact: mpychan4-c@my.cityu.edu.hk
Repository: https://github.com/SCR139/ScamScanBeta_FYP
================================================================================
1.  OVERVIEW
================================================================================

ScamScan Beta is a production‑ready phishing detection system that combines a
character‑level Transformer with 82 engineered features and an optional page
content analyzer. Unlike most academic models that rely on static dataset
splits, ScamScan Beta is validated on live, unseen PhishTank URLs collected
after training.

Key results on 2,130 live phishing URLs:

    Accuracy:   96.14%
    Precision:  99.79%
    Recall:     96.05%
    F1-Score:   97.89%

The system is designed for real‑time deployment, with parallel batch
processing, adaptive timeouts, a circuit breaker for dead sites, and smart
caching.

================================================================================
2.  SYSTEM ARCHITECTURE (5 Layers)
================================================================================

Layer 1 – Input Processing & Normalization
    Parses URL components and normalises homoglyphs (0→o, 1→l, @→a).

Layer 2 – Multi‑Modal Feature Extraction
    • Pathway A: Transformer encoder (1 layer, 8 heads) → 128‑dim URL embedding
    • Pathway B: 82 engineered features → MLP → 32‑dim feature embedding
    • Pathway C: Page content analyzer (optional) → phishing score 0‑1

Layer 3 – Feature Fusion
    Concatenates all embeddings into a single 160‑dim vector.

Layer 4 – Deep Fusion Network
    Dense(64) → BN → ReLU → Dropout(0.2) → Dense(32) → BN → ReLU → Dropout(0.2)
    → Dense(2) → Softmax.

Layer 5 – 9‑Level Hierarchical Decision Fusion
    Deterministic rules (Google Safe Browsing, credit card fields, brand
    impersonation, page score, AI confidence) produce the final verdict.

================================================================================
3.  DATASETS
================================================================================

ScamScan Beta is trained on three complementary datasets:

    Dataset               | Samples  | Features  | Role
    ----------------------|----------|-----------|----------------------------
    URL dataset           | 450,176  | 16 basic  | Broad coverage
    Training dataset      | 197,307  | 87 advanced| Deep feature diversity
    Mendeley dataset      | 101,219  | 16 stat.  | Academic benchmark

All three are combined into a single balanced set (100,000 samples, 50/50
phishing/legitimate) before training.

Download instructions:
    • URL dataset:      [provide URL]
    • Training dataset: [provide URL]
    • Mendeley dataset: [provide URL]

Place the files in:
    ./data/raw/URL dataset.csv
    ./data/raw/dataset_training.csv
    ./src/medeley_data.csv

================================================================================
4.  INSTALLATION
================================================================================

System requirements:
    • Python 3.10 or higher
    • 16 GB RAM (recommended)
    • Apple M2 (MPS) or NVIDIA GPU (optional, but faster)

Create a virtual environment and install dependencies:

    python -m venv venv
    source venv/bin/activate          # Windows: venv\Scripts\activate
    pip install -r requirements.txt

Example requirements.txt:

    torch>=2.0.0
    pandas>=1.3.0
    numpy>=1.21.0
    scikit-learn>=1.0.0
    beautifulsoup4>=4.10.0
    requests>=2.25.0
    tqdm>=4.64.0
    matplotlib>=3.5.0

================================================================================
5.  TRAINING THE MODEL
================================================================================

Run the training script from the project root:

    python src/initial_transformer.py --base-path . --epochs 30 --save initial_model.pkl

Options:
    --base-path   Directory containing the datasets (default: current directory)
    --epochs      Number of training epochs (default: 30)
    --save        Output model file path (default: initial_model.pkl)
    --device      Device to use: auto, cpu, cuda, mps (default: auto)

Expected output after 30 epochs:
    Best validation accuracy: >98.8%
    Test on sample URLs:
        https://www.google.com            → Phishing: False (Probability: 0.004)
        https://www.facebook.com          → Phishing: False (Probability: 0.006)
        https://paypal.com.security-verify.com/login → Phishing: True (Prob: 0.995)

================================================================================
6.  USING THE DETECTOR
================================================================================

After training, you can run the complete 5‑layer detector:

    from src.ultimate_detector import EnhancedUltimatePhishingDetector

    detector = EnhancedUltimatePhishingDetector(model_path='initial_model.pkl')
    result = detector.analyze_enhanced('https://example.com')
    print(result['verdict'], result['confidence'])

To analyse many URLs in parallel:

    urls = ['https://google.com', 'https://paypal.com.security-verify.com/login']
    results = detector.analyze_batch(urls, max_workers=10)
    for r in results:
        print(f"{r['url']}: {r['verdict']} ({r['confidence']:.1%})")

================================================================================
7.  TESTING ON LIVE PHISHTANK URLS
================================================================================

To reproduce the evaluation reported in the paper:

    python src/enhanced_phishtank_tester.py

This script will:
    • Download the latest verified phishing URLs from PhishTank (public snapshot)
    • Generate legitimate URLs from the Tranco top list
    • Test ScamScan Beta on up to 2,000 phishing + 1,000 legitimate URLs
    • Output detailed results (CSV, JSON, missed URLs list, visualisation)

Expected results (as reported in the paper):

    True Positives:  1,921 (96.05%)
    False Negatives:    79 ( 3.95%)
    True Negatives:    146 (97.33%)
    False Positives:     4 ( 2.67%)

    Accuracy:  96.14%
    Precision: 99.79%
    Recall:    96.05%
    F1-Score:  97.89%

Output files are written to the current directory:
    phishtank_test_results_*.csv
    phishtank_test_results_*.json
    missed_phishing_*.txt
    phishtank_analysis_*.png

================================================================================
8.  API KEYS (OPTIONAL)
================================================================================

Google Safe Browsing and Whois API are optional but improve detection.
If you wish to use them, set environment variables:

    export GOOGLE_SAFE_BROWSING_KEY='your_key_here'
    export WHOIS_API_KEY='your_key_here'

Alternatively, create a configuration file:
    configs/api_keys.json

    {
        "google_safe_browsing": "your_key_here",
        "whois_api": "your_key_here",
        "usage_limits": {
            "google_daily": 10000,
            "whois_daily": 500
        }
    }

Without these keys, the detector still works using the AI model and page
analysis alone (Google Safe Browsing and WHOIS are simply skipped).

================================================================================
9.  PROJECT STRUCTURE
================================================================================

scamscan-beta/
│
├── README.txt                      # This file
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment variable template
├── .gitignore                      # Ignore secrets, cache, datasets
│
├── src/
│   ├── initial_transformer.py      # Core AI model (Transformer + features)
│   ├── ultimate_detector.py        # 5‑layer ensemble detector
│   ├── api_manager.py              # Google Safe Browsing / Whois wrapper
│   ├── enhanced_phishtank_tester.py # Live PhishTank evaluation suite
│   └── brands.json                 # Brand impersonation database
│
├── data/
│   ├── raw/                        # Place datasets here (not in repository)
│   └── processed/                  # Generated balanced datasets (ignored)
│
├── results/                        # Test outputs (CSV, JSON, plots)
├── models/                         # Saved model checkpoints
└── logs/                           # Training logs (optional)

================================================================================
10.  CITATION
================================================================================

If you use ScamScan Beta in your research, please cite:

    PakYuMarco, Chan. (2026). ScamScan Beta: A Multi‑Modal Transformer with
    Hierarchical Decision Fusion for Real‑World Phishing Detection.

For the datasets and baseline comparisons:

    Aljofey, A., Qasem, Z. A. H., Lu, J., Xu, C., Liu, Z., & Zou, Y. (2026).
    A hybrid deep learning model for robust phishing URL detection.
    Computers & Security, 142, 104267.

    Basystiuk, L., & Lutska-Hrabovska, K. (2026). Deterministic Boolean-algebra
    framework for interpretable and energy-efficient phishing URL detection.
    Applied Sciences, 16(5), 2170.

================================================================================
11.  LICENSE
================================================================================

This project is released under the MIT License. See the LICENSE file for details.

================================================================================
12.  CONTACT
================================================================================

For questions, issues, or collaboration, please contact:

    Chan Pak Yu Marco
    mpychan4-c@my.cityu.edu.hk
    [GitHub Issues URL]

================================================================================
                            SCAMSCAN BETA  –  VERSION 1.0
================================================================================
