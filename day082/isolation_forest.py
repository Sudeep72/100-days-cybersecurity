#!/usr/bin/env python3
"""
Day 082 - Isolation Forest for Security Anomaly Detection
100 Days of Cybersecurity by Sudeep Ravichandran

Detects anomalies in security data (login patterns, data access, etc.)
using Isolation Forest algorithm.

Usage:
    python3 isolation_forest.py --data login_logs.csv --contamination 0.05
    python3 isolation_forest.py --data login_logs.csv --model model.pkl --predict
"""

import pandas as pd
import numpy as np
import pickle
import argparse
import json
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime
from typing import Dict, List, Tuple
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA

class SecurityAnomalyDetector:
    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = []
        self.fitted = False

    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Engineer features from raw security data"""
        df = df.copy()
        
        # Parse timestamp
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Temporal features
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        
        # Time since last login (per user)
        df = df.sort_values(['user', 'timestamp'])
        df['time_since_last_login_hours'] = df.groupby('user')['timestamp'].diff().dt.total_seconds() / 3600
        df['time_since_last_login_hours'].fillna(0, inplace=True)
        
        # Capped at 24 hours (prevents extreme values)
        df['time_since_last_login_hours'] = df['time_since_last_login_hours'].clip(0, 24)
        
        # Logins in past 24 hours (rate)
        time_window = pd.Timedelta(hours=24)
        df['logins_in_24h'] = df.groupby('user').apply(
            lambda x: x['timestamp'].rolling(time_window).count()
        ).reset_index(0, drop=True).values
        
        # Distance calculation (simplified, assumes lat/lon exist)
        if 'location_lat' in df.columns and 'location_lon' in df.columns:
            df['distance_from_home_km'] = np.abs(
                df['location_lat'] - 40.7128  # NYC office lat
            ) * 111 + np.abs(
                df['location_lon'] - (-74.0060)  # NYC office lon
            ) * 111
            df['distance_from_home_km'] = df['distance_from_home_km'].clip(0, 20000)
        
        # Data access features
        if 'bytes_downloaded' in df.columns:
            df['bytes_downloaded'] = df['bytes_downloaded'].fillna(0)
            df['log_bytes_downloaded'] = np.log1p(df['bytes_downloaded'])
        
        if 'files_accessed' in df.columns:
            df['files_accessed'] = df['files_accessed'].fillna(0)
        
        # Country diversity
        if 'country' in df.columns:
            df['countries_in_24h'] = df.groupby('user')['country'].rolling(time_window).nunique().reset_index(0, drop=True).values
        
        return df

    def prepare_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, List[str]]:
        """Select and prepare features for training"""
        feature_columns = []
        
        # Always include temporal
        temporal_cols = ['hour', 'day_of_week', 'is_weekend']
        feature_columns.extend([col for col in temporal_cols if col in df.columns])
        
        # Include time-based
        if 'time_since_last_login_hours' in df.columns:
            feature_columns.append('time_since_last_login_hours')
        
        if 'logins_in_24h' in df.columns:
            feature_columns.append('logins_in_24h')
        
        # Include location if available
        if 'distance_from_home_km' in df.columns:
            feature_columns.append('distance_from_home_km')
        
        # Include data access
        if 'log_bytes_downloaded' in df.columns:
            feature_columns.append('log_bytes_downloaded')
        
        if 'files_accessed' in df.columns:
            feature_columns.append('files_accessed')
        
        # Include diversity
        if 'countries_in_24h' in df.columns:
            feature_columns.append('countries_in_24h')
        
        self.feature_names = feature_columns
        
        # Extract features and handle missing values
        X = df[feature_columns].copy()
        X = X.fillna(X.mean())
        
        return X.values, feature_columns

    def train(self, df: pd.DataFrame):
        """Train Isolation Forest on security data"""
        print("[*] Preparing features...")
        df_engineered = self.engineer_features(df)
        
        print(f"[*] Using features: {self.feature_names if self.feature_names else 'Will select automatically'}")
        X, features = self.prepare_features(df_engineered)
        
        print(f"[*] Training Isolation Forest (contamination={self.contamination})...")
        print(f"[*] Data shape: {X.shape} ({X.shape[0]} samples, {X.shape[1]} features)")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=100,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_scaled)
        self.fitted = True
        
        print("[+] Model trained successfully")
        
        return df_engineered

    def detect_anomalies(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect anomalies in new data"""
        if not self.fitted:
            raise ValueError("Model not trained. Call train() first.")
        
        print("[*] Engineering features for detection...")
        df_engineered = self.engineer_features(df)
        
        print("[*] Scaling features...")
        X, _ = self.prepare_features(df_engineered)
        X_scaled = self.scaler.transform(X)
        
        print("[*] Detecting anomalies...")
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)
        
        # Add results
        df_engineered['is_anomaly'] = predictions == -1
        df_engineered['anomaly_score'] = scores
        df_engineered['anomaly_severity'] = np.maximum(0, -scores)  # Make positive
        
        return df_engineered

    def get_anomalies(self, df: pd.DataFrame, threshold: float = 0.5) -> pd.DataFrame:
        """Extract anomalies above threshold"""
        return df[df['anomaly_score'] < -threshold].sort_values('anomaly_score')

    def save_model(self, filepath: str):
        """Save trained model"""
        if not self.fitted:
            raise ValueError("Model not trained. Call train() first.")
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'contamination': self.contamination
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"[+] Model saved to {filepath}")

    def load_model(self, filepath: str):
        """Load trained model"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.contamination = model_data['contamination']
        self.fitted = True
        
        print(f"[+] Model loaded from {filepath}")

    def visualize_anomalies(self, df: pd.DataFrame, output_file: str = 'anomalies.png'):
        """Visualize anomalies using PCA"""
        print("[*] Visualizing anomalies using PCA...")
        
        X, _ = self.prepare_features(df)
        X_scaled = self.scaler.transform(X)
        
        # PCA to 2D
        pca = PCA(n_components=2)
        X_pca = pca.fit_transform(X_scaled)
        
        # Plot
        plt.figure(figsize=(12, 8))
        
        normal = df['is_anomaly'] == False
        anomalies = df['is_anomaly'] == True
        
        plt.scatter(X_pca[normal, 0], X_pca[normal, 1], c='blue', label='Normal', alpha=0.6)
        plt.scatter(X_pca[anomalies, 0], X_pca[anomalies, 1], c='red', label='Anomaly', alpha=0.8, s=100)
        
        plt.xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.1%})')
        plt.ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.1%})')
        plt.title('Security Anomalies (PCA Projection)')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.savefig(output_file)
        print(f"[+] Visualization saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(description='Isolation Forest Security Anomaly Detector - Day 082')
    parser.add_argument('--data', required=True, help='Path to CSV data file')
    parser.add_argument('--contamination', type=float, default=0.05, help='Expected anomaly rate (0-1)')
    parser.add_argument('--model', help='Path to save/load model')
    parser.add_argument('--predict', action='store_true', help='Use for prediction only (requires model)')
    parser.add_argument('--threshold', type=float, default=0.5, help='Anomaly score threshold')
    parser.add_argument('--output', help='Output JSON file for results')
    parser.add_argument('--visualize', action='store_true', help='Create visualization')
    
    args = parser.parse_args()
    
    print("[*] Security Anomaly Detector - Day 082")
    print("[*] Using Isolation Forest for unsupervised anomaly detection\n")
    
    # Load data
    print(f"[*] Loading data from {args.data}...")
    df = pd.read_csv(args.data)
    print(f"[+] Loaded {len(df)} records\n")
    
    # Initialize detector
    detector = SecurityAnomalyDetector(contamination=args.contamination)
    
    if args.predict and args.model:
        # Prediction mode
        print("[*] Loading pre-trained model...")
        detector.load_model(args.model)
        
        print("[*] Running anomaly detection...")
        results = detector.detect_anomalies(df)
        
    else:
        # Training mode
        print("[*] Training Isolation Forest...")
        results = detector.train(df)
        
        print("[*] Detecting anomalies...")
        results = detector.detect_anomalies(df)
        
        if args.model:
            detector.save_model(args.model)
    
    # Extract and display anomalies
    anomalies = detector.get_anomalies(results, threshold=args.threshold)
    
    print(f"\n[+] Found {len(anomalies)} anomalies (score < -{args.threshold}):")
    print(f"    Total records: {len(results)}")
    print(f"    Anomaly rate: {len(anomalies) / len(results) * 100:.1f}%\n")
    
    if len(anomalies) > 0:
        print("Top 10 anomalies:")
        print(anomalies[['user', 'timestamp', 'anomaly_score', 'hour', 'logins_in_24h']].head(10))
    
    # Save results
    if args.output:
        output_data = {
            'summary': {
                'total_records': len(results),
                'anomalies_detected': len(anomalies),
                'anomaly_rate': float(len(anomalies) / len(results)),
                'contamination': args.contamination,
                'threshold': args.threshold
            },
            'anomalies': anomalies.to_dict('records')
        }
        
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
        
        print(f"\n[+] Results saved to {args.output}")
    
    # Visualization
    if args.visualize:
        detector.visualize_anomalies(results)


if __name__ == "__main__":
    main()