#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Isolation Forest Model Trainer for C2 Detection

This script fetches a baseline of 'normal' network traffic from Elasticsearch,
engineers features, and trains an Isolation Forest model to detect anomalies.
The trained model and a feature scaler are saved to disk for use by the main
detection script.

Usage:
1.  Ensure you have a representative period of normal traffic in Elasticsearch.
2.  Adjust the `TRAINING_TIMEFRAME_DAYS` variable below.
3.  Run the script: `python train_model.py`
"""

import logging
import pandas as pd
from datetime import datetime, timedelta, timezone
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# --- Import necessary components from the main analyzer ---
# (Assuming train_model.py is in the same directory as analyzer.py)
from analyzer import C2Analyzer, load_config, CONFIG_FILE

# --- Configuration ---
# Define how far back to look for training data.
# This should be a period of known-good, "normal" activity.
TRAINING_TIMEFRAME_DAYS = 7

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def train_model():
    """Fetches data, trains the model, and saves it."""
    config = load_config(CONFIG_FILE)
    if not config['ml_model']['enabled']:
        logging.warning("ML model is disabled in config.yaml. Aborting training.")
        return

    analyzer = C2Analyzer(config)

    # --- 1. Fetch Baseline Data ---
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=TRAINING_TIMEFRAME_DAYS)
    logging.info(f"Fetching training data from {start_time} to {end_time}...")
    
    raw_data = analyzer.fetch_data(start_time, end_time)
    if not raw_data['conn']:
        logging.error("No connection data found for the training period. Cannot train model.")
        return

    # --- 2. Enrich Data and Engineer Features ---
    logging.info("Enriching data and engineering features...")
    enriched_connections = analyzer._enrich_connections(raw_data)
    
    if not enriched_connections:
        logging.error("No enriched connections were created. Cannot train model.")
        return

    # Define the feature set for the model
    feature_names = [
        'duration', 'orig_bytes', 'resp_bytes',
        'dns_query_entropy', 'http_uri_entropy',
        'ja3_rarity', 'user_agent_rarity'
    ]
    
    # Create a DataFrame from the enriched data
    df = pd.DataFrame(enriched_connections)
    df = df.fillna(0) # Fill missing values with 0
    
    # Ensure all required feature columns exist
    for col in feature_names:
        if col not in df.columns:
            df[col] = 0
            
    df_features = df[feature_names]

    logging.info(f"Training on {len(df_features)} samples with {len(feature_names)} features.")

    # --- 3. Scale Features ---
    logging.info("Scaling features...")
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(df_features)

    # --- 4. Train Isolation Forest Model ---
    logging.info("Training Isolation Forest model...")
    contamination = config['ml_model'].get('contamination', 0.01)
    iso_forest = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100
    )
    iso_forest.fit(scaled_features)
    logging.info("Model training complete.")

    # --- 5. Save Model and Scaler ---
    model_path = config['ml_model']['model_path']
    scaler_path = config['ml_model']['scaler_path']
    
    try:
        joblib.dump(iso_forest, model_path)
        joblib.dump(scaler, scaler_path)
        logging.info(f"Model saved to {model_path}")
        logging.info(f"Scaler saved to {scaler_path}")
    except Exception as e:
        logging.error(f"Failed to save model/scaler: {e}")

if __name__ == '__main__':
    train_model()
