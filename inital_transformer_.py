"""
Initial Transformer Phishing System

Trains a character‑level Transformer on three combined datasets with perfect
50/50 balancing. The model fuses URL character embeddings with engineered
features and outputs a phishing probability.

This is the core AI model used by the ScamScan Beta detector.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score
from urllib.parse import urlparse
import re
import os
import argparse
import warnings

warnings.filterwarnings('ignore')


class CharacterMappingManager:
    """Maps characters to indices for URL tokenization."""

    def __init__(self):
        self.chars = 'abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&\'()*+,;=%'
        self.char_to_idx = {char: idx + 1 for idx, char in enumerate(self.chars)}
        self.char_to_idx['<PAD>'] = 0
        self.char_to_idx['<UNK>'] = len(self.chars) + 1
        self.vocab_size = len(self.char_to_idx)

    def encode(self, url, max_length=200):
        """Convert a URL string to a list of character indices."""
        indices = []
        url = str(url).lower()[:max_length]
        for ch in url:
            idx = self.char_to_idx.get(ch, self.char_to_idx['<UNK>'])
            indices.append(idx)
        if len(indices) < max_length:
            indices.extend([0] * (max_length - len(indices)))
        return indices[:max_length]


class TransformerEncoder(nn.Module):
    """Single‑layer Transformer encoder for URL character sequences."""

    def __init__(self, vocab_size, embed_dim=128, num_heads=8):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.pos_encoding = nn.Parameter(torch.randn(1, 200, embed_dim) * 0.1)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=num_heads, batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=1)
        self.classifier = nn.Linear(embed_dim, 2)

    def forward(self, x):
        x = self.embedding(x) + self.pos_encoding[:, :x.size(1), :]
        x = self.transformer(x).mean(dim=1)
        return self.classifier(x)


class DatasetLoader:
    """Loads and preprocesses the three training datasets."""

    def __init__(self):
        self.label_encoder = LabelEncoder()

    def load_url_dataset(self, filepath):
        """Load URL dataset (simple URL + type)."""
        print(f"\n📥 Loading URL dataset: {filepath}")
        df = pd.read_csv(filepath)
        urls = df['url'].values
        labels = np.array([1 if str(l).lower() == 'legitimate' else 0
                           for l in df['type'].values])
        print(f"   → {len(urls)} samples (Phishing: {np.sum(labels==0)}, "
              f"Legit: {np.sum(labels==1)})")
        return urls, labels

    def load_training_dataset(self, filepath):
        """Load dataset_training.csv (87 engineered features)."""
        print(f"\n📥 Loading training dataset: {filepath}")
        df = pd.read_csv(filepath)

        if 'status' in df.columns:
            df = df.drop('status', axis=1)
            print("   ✅ Removed 'status' column")

        urls = df['url'].values
        labels = df['label'].values.astype(np.int64)

        feature_cols = [c for c in df.columns if c not in ['url', 'label']]
        features = df[feature_cols].values.astype(np.float32)
        features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

        print(f"   → {len(urls)} samples with {features.shape[1]} features")
        print(f"      Phishing: {np.sum(labels==0)}, Legit: {np.sum(labels==1)}")
        print(f"      Feature range: [{features.min():.2f}, {features.max():.2f}]")
        return urls, labels, features

    def load_mendeley_dataset(self, filepath):
        """Load Mendeley dataset (16 statistical features)."""
        print(f"\n📥 Loading Mendeley dataset: {filepath}")
        df = pd.read_csv(filepath)

        urls = df['URL'].values
        labels = df['ClassLabel'].values.astype(np.int64)   # 0=phishing, 1=legitimate

        feature_cols = [c for c in df.columns if c not in ['URL', 'ClassLabel']]
        features = df[feature_cols].values.astype(np.float32)
        features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

        print(f"   → {len(urls)} samples with {features.shape[1]} features")
        print(f"      Phishing: {np.sum(labels==0)}, Legit: {np.sum(labels==1)}")
        return urls, labels, features


class InitialTransformer:
    """Main model trainer and predictor."""

    def __init__(self, device='auto'):
        if device == 'auto':
            if torch.cuda.is_available():
                self.device = torch.device('cuda')
            elif torch.backends.mps.is_available():
                self.device = torch.device('mps')
            else:
                self.device = torch.device('cpu')
        else:
            self.device = torch.device(device)

        print(f"🚀 Using device: {self.device}")

        self.char_mapping = CharacterMappingManager()
        self.loader = DatasetLoader()
        self.model = None
        self.scaler = StandardScaler()

    def load_all_data(self, base_path):
        """Load and combine the three datasets."""
        print("\n" + "="*60)
        print("📚 LOADING ALL DATASETS")
        print("="*60)

        all_urls = []
        all_labels = []
        all_features_87 = []
        all_features_16 = []
        dataset_sources = []

        # URL dataset
        url_path = os.path.join(base_path, 'URL dataset.csv')
        if os.path.exists(url_path):
            urls, labels = self.loader.load_url_dataset(url_path)
            all_urls.extend(urls)
            all_labels.extend(labels)
            dataset_sources.extend(['url'] * len(urls))

        # Training dataset (87 features)
        train_path = os.path.join(base_path, 'dataset_training.csv')
        if os.path.exists(train_path):
            urls, labels, features = self.loader.load_training_dataset(train_path)
            all_urls.extend(urls)
            all_labels.extend(labels)
            all_features_87.extend(features)
            dataset_sources.extend(['train'] * len(urls))

        # Mendeley dataset (16 features)
        mendeley_path = os.path.join(base_path, 'src', 'medeley_data.csv')
        if os.path.exists(mendeley_path):
            urls, labels, features = self.loader.load_mendeley_dataset(mendeley_path)
            all_urls.extend(urls)
            all_labels.extend(labels)
            all_features_16.extend(features)
            dataset_sources.extend(['mendeley'] * len(urls))

        # Convert to numpy arrays
        all_urls = np.array(all_urls)
        all_labels = np.array(all_labels)
        all_features_87 = np.array(all_features_87) if all_features_87 else None
        all_features_16 = np.array(all_features_16) if all_features_16 else None
        dataset_sources = np.array(dataset_sources)

        print(f"\n📊 TOTAL COMBINED:")
        print(f"   Samples: {len(all_urls)}")
        print(f"   Phishing: {np.sum(all_labels==0)} "
              f"({np.sum(all_labels==0)/len(all_labels)*100:.1f}%)")
        print(f"   Legitimate: {np.sum(all_labels==1)} "
              f"({np.sum(all_labels==1)/len(all_labels)*100:.1f}%)")
        return all_urls, all_labels, all_features_87, all_features_16, dataset_sources

    def balance_data(self, urls, labels, features_87, features_16, sources):
        """Balance dataset to a perfect 50/50 split (50k each)."""
        print("\n" + "="*60)
        print("⚖️  BALANCING DATA")
        print("="*60)

        phishing_idx = np.where(labels == 0)[0]
        legit_idx = np.where(labels == 1)[0]

        print(f"\nBefore balancing:")
        print(f"   Phishing: {len(phishing_idx)} samples")
        print(f"   Legitimate: {len(legit_idx)} samples")

        sample_size = min(50000, len(phishing_idx), len(legit_idx))

        np.random.seed(42)
        phishing_sample = np.random.choice(phishing_idx, sample_size, replace=False)
        legit_sample = np.random.choice(legit_idx, sample_size, replace=False)

        balanced_idx = np.concatenate([phishing_sample, legit_sample])
        np.random.shuffle(balanced_idx)

        balanced_urls = urls[balanced_idx]
        balanced_labels = labels[balanced_idx]
        balanced_sources = sources[balanced_idx]

        if features_87 is not None:
            balanced_features_87 = np.zeros((len(balanced_idx), features_87.shape[1]),
                                            dtype=np.float32)
            for i, idx in enumerate(balanced_idx):
                if idx < len(features_87):
                    balanced_features_87[i] = features_87[idx]
        else:
            balanced_features_87 = None

        if features_16 is not None:
            balanced_features_16 = np.zeros((len(balanced_idx), features_16.shape[1]),
                                            dtype=np.float32)
            for i, idx in enumerate(balanced_idx):
                if idx < len(features_16):
                    balanced_features_16[i] = features_16[idx]
        else:
            balanced_features_16 = None

        print(f"\nAfter balancing:")
        print(f"   Total: {len(balanced_urls)} samples")
        print(f"   Phishing: {np.sum(balanced_labels == 0)}")
        print(f"   Legitimate: {np.sum(balanced_labels == 1)}")
        return (balanced_urls, balanced_labels,
                balanced_features_87, balanced_features_16, balanced_sources)

    @staticmethod
    def extract_features_from_url(url):
        """Extract 16 basic URL features (fallback for datasets without precomputed features)."""
        url = str(url)
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path

        features = [
            len(url),
            1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
            url.count('.'),
            1 if url.startswith('https') else 0,
            0,  # url_entropy (simplified)
            0,  # token_count (simplified)
            max(0, len(domain.split('.')) - 2),
            len(parsed.query.split('&')) if parsed.query else 0,
            len(domain.split('.')[-1]),
            len(path),
            1 if '-' in domain else 0,
            sum(c.isdigit() for c in url),
            1,  # tld_popularity (simplified)
            1 if any(ext in path for ext in ['.exe', '.zip', '.scr']) else 0,
            len(domain.split('.')[0]),
            sum(c.isdigit() for c in url) / len(url) if url else 0
        ]
        return np.array(features, dtype=np.float32)

    def prepare_features(self, urls, features_87, features_16):
        """Combine all features into a single 82‑dimensional matrix."""
        print("\n🔧 Preparing unified features...")
        feature_matrices = []

        for i, url in enumerate(urls):
            url_features = self.extract_features_from_url(url)

            if features_87 is not None and i < len(features_87):
                feat_87 = features_87[i]
                feat_87 = (feat_87[:50] if len(feat_87) > 50
                           else np.pad(feat_87, (0, 50 - len(feat_87))))
            else:
                feat_87 = np.zeros(50, dtype=np.float32)

            if features_16 is not None and i < len(features_16):
                feat_16 = features_16[i]
            else:
                feat_16 = np.zeros(16, dtype=np.float32)

            combined = np.concatenate([url_features, feat_87, feat_16])
            feature_matrices.append(combined)

        features = np.array(feature_matrices, dtype=np.float32)
        print(f"   Feature matrix shape: {features.shape}")
        return features

    def train(self, base_path, epochs=30, batch_size=32):
        """Run the full training pipeline."""
        print("\n" + "="*60)
        print("🎯 INITIAL TRANSFORMER TRAINER")
        print("="*60)

        # 1. Load all data
        urls, labels, f87, f16, sources = self.load_all_data(base_path)

        # 2. Balance
        urls, labels, f87, f16, sources = self.balance_data(urls, labels, f87, f16, sources)

        # 3. Prepare features
        features = self.prepare_features(urls, f87, f16)

        # 4. Scale features
        print("\n📊 Scaling features...")
        features_scaled = self.scaler.fit_transform(features)

        # 5. Train/test split
        X_train, X_test, y_train, y_test, url_train, url_test = train_test_split(
            features_scaled, labels, urls, test_size=0.2, random_state=42, stratify=labels
        )

        print(f"\n✅ FINAL DATASET:")
        print(f"   Train: {len(url_train)} samples")
        print(f"   Test: {len(url_test)} samples")
        print(f"   Features per sample: {X_train.shape[1]}")

        # 6. Create PyTorch datasets
        class URLFeatureDataset(Dataset):
            def __init__(self, urls, features, labels, char_map):
                self.urls = urls
                self.features = torch.FloatTensor(features)
                self.labels = torch.LongTensor(labels)
                self.encoded_urls = torch.LongTensor([char_map.encode(u) for u in urls])

            def __len__(self):
                return len(self.labels)

            def __getitem__(self, idx):
                return {
                    'url_seq': self.encoded_urls[idx],
                    'features': self.features[idx],
                    'label': self.labels[idx]
                }

        train_dataset = URLFeatureDataset(url_train, X_train, y_train, self.char_mapping)
        test_dataset = URLFeatureDataset(url_test, X_test, y_test, self.char_mapping)

        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

        # 7. Build model
        self.model = TransformerEncoder(self.char_mapping.vocab_size).to(self.device)
        total_params = sum(p.numel() for p in self.model.parameters())
        print(f"\n✅ Model built with {total_params:,} parameters")

        # 8. Training loop
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=0.0001)
        torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)

        print("\n🚂 Starting training...")
        best_acc = 0

        for epoch in range(epochs):
            self.model.train()
            train_loss = 0
            for batch in train_loader:
                url_seq = batch['url_seq'].to(self.device)
                labels = batch['label'].to(self.device)

                optimizer.zero_grad()
                outputs = self.model(url_seq)
                loss = criterion(outputs, labels)
                loss.backward()
                optimizer.step()
                train_loss += loss.item()

            # Evaluation
            self.model.eval()
            all_preds, all_labels = [], []
            with torch.no_grad():
                for batch in test_loader:
                    url_seq = batch['url_seq'].to(self.device)
                    labels = batch['label'].to(self.device)
                    outputs = self.model(url_seq)
                    preds = torch.argmax(outputs, dim=1)
                    all_preds.extend(preds.cpu().numpy())
                    all_labels.extend(labels.cpu().numpy())

            acc = accuracy_score(all_labels, all_preds)
            if (epoch + 1) % 5 == 0:
                print(f"Epoch {epoch+1}/{epochs} | Loss: {train_loss/len(train_loader):.4f} "
                      f"| Val Acc: {acc:.4f}")

            if acc > best_acc:
                best_acc = acc
                torch.save(self.model.state_dict(), 'best_model.pt')

        print(f"\n✅ Best validation accuracy: {best_acc:.4f}")
        self.model.load_state_dict(torch.load('best_model.pt'))
        return self.model

    def predict(self, url):
        """Predict the probability that a URL is phishing."""
        self.model.eval()
        url_encoded = torch.LongTensor([self.char_mapping.encode(url)]).to(self.device)

        with torch.no_grad():
            outputs = self.model(url_encoded)
            probs = F.softmax(outputs, dim=1)

        prob = probs[0, 0].item()   # index 0 = phishing class
        return {
            'is_phishing': prob > 0.5,
            'probability': prob,
            'confidence': abs(prob - 0.5) * 2
        }

    def load(self, filepath):
        """Load a previously saved model and scaler."""
        checkpoint = torch.load(filepath, map_location=self.device, weights_only=False)
        self.model = TransformerEncoder(checkpoint['vocab_size']).to(self.device)
        self.model.load_state_dict(checkpoint['model_state'])
        self.scaler.__dict__.update(checkpoint['scaler_state'])
        self.model.eval()
        print(f"✅ Model loaded from {filepath}")
        return self

    def save(self, filepath):
        """Save the model and scaler parameters."""
        torch.save({
            'model_state': self.model.state_dict(),
            'scaler_state': self.scaler.__dict__,
            'vocab_size': self.char_mapping.vocab_size
        }, filepath)
        print(f"\n💾 Model saved to {filepath}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-path', type=str, default='.',
                        help='Base directory containing the datasets')
    parser.add_argument('--epochs', type=int, default=30,
                        help='Number of training epochs')
    parser.add_argument('--save', type=str, default='initial_model.pkl',
                        help='Output model file path')
    parser.add_argument('--device', type=str, default='auto',
                        choices=['cpu', 'cuda', 'mps', 'auto'],
                        help='Device to use for training')
    args = parser.parse_args()

    model = InitialTransformer(device=args.device)
    model.train(args.base_path, epochs=args.epochs)
    model.save(args.save)

    # Quick test
    print("\n🔍 Testing...")
    test_urls = [
        'https://www.google.com',
        'https://www.facebook.com',
        'https://paypal.com.security-verify.com/login'
    ]
    for url in test_urls:
        res = model.predict(url)
        print(f"\n{url}\n   Phishing: {res['is_phishing']}\n   Probability: {res['probability']:.4f}")


if __name__ == "__main__":
    main()