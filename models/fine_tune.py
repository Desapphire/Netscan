import sys
import os
import yaml
import joblib
import numpy as np
import pandas as pd
from sqlalchemy import create_engine
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from itertools import product
from joblib import Parallel, delayed

# Optimization for Linux: prevent thread contention across cores
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

if sys.platform != "win32":
    try:
        os.nice(10)  # De-prioritise so capture remains real-time
    except AttributeError:
        pass

# Load config
base_dir = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(base_dir, 'ml_config.yaml')
with open(CONFIG_PATH, 'r') as f:
    ml_cfg = yaml.safe_load(f)

project_root = os.path.dirname(base_dir)
OUTPUT_PATH = ml_cfg.get('training', {}).get('output_path', './models/isolation_forest.pkl')
if OUTPUT_PATH.startswith('./'):
    OUTPUT_PATH = os.path.join(project_root, OUTPUT_PATH[2:])
elif not os.path.isabs(OUTPUT_PATH):
    OUTPUT_PATH = os.path.join(project_root, OUTPUT_PATH)
FEATURE_COLS = ml_cfg['features']
MIN_SAMPLES = ml_cfg.get('training', {}).get('min_samples', 500)

# Samples for unsupervised validation
SAMPLES = {
    'VPN (OpenVPN)': [45, 3, 1, 8e6, 25e6, 1300, 50, 0.01, 0.002, 0, 45, 1, 1, 1194, 0.9, 0.0],
    'Gambling':      [80, 15, 6, 1e6, 7e6, 700, 300, 0.05, 0.03, 80, 0, 20, 2, 443, 0.0, 0.7],
    'Torrent':       [200, 60, 2, 15e6, 40e6, 1000, 300, 0.005, 0.003, 120, 80, 5, 20, 6881, 0.1, 0.3],
    'Malware C2':    [10, 2, 1, 5e3, 1e4, 90, 50, 0.8, 0.5, 10, 0, 5, 1, 8080, 0.0, 0.95],
    'Hacking/Scan':  [500, 300, 250, 2e5, 5e4, 60, 40, 0.001, 0.001, 500, 0, 10, 400, 22, 0.2, 0.8],
    'Normal':        [12, 5, 4, 2e5, 1.5e6, 600, 250, 0.2, 0.15, 12, 0, 4, 2, 443, 0.0, 0.0],
}
# Expected predictions: 1 for normal, -1 for anomalies
EXPECTED_PREDS = {
    'VPN (OpenVPN)': -1,
    'Gambling': -1,
    'Torrent': -1,
    'Malware C2': -1,
    'Hacking/Scan': -1,
    'Normal': 1
}

def load_data():
    project_root = os.path.dirname(base_dir)
    db_path = os.path.join(project_root, 'netscan.db')

    DB_URL = f'sqlite:///{db_path}'
    engine = create_engine(DB_URL)
    try:
        df = pd.read_sql_table('network_features', engine)
    except ValueError:
        print("Could not load table 'network_features'. Did you capture traffic?")
        return None
    return df

def main():
    print("Starting Fine-tuning process...")
    df = load_data()
    if df is None or len(df) == 0:
        print("Insufficient data for training. Tuning typically requires network_features rows.")
        X = np.empty((0, len(FEATURE_COLS)))
    else:
        X = df[FEATURE_COLS].fillna(0).values.astype(float)
        
    # Generate some dummy data if we really have none so the user can test the script
    if len(X) == 0:
        print("WARNING: No data found in database. Using synthetic background noise for test-run.")
        # Synthetic data generator
        np.random.seed(42)
        X = np.abs(np.random.normal(loc=[10, 5, 3, 1e5, 5e5, 400, 200, 0.3, 0.1, 10, 0, 3, 2, 443, 0, 0], scale=[5, 2, 1, 5e4, 2e5, 100, 50, 0.1, 0.05, 5, 0, 2, 1, 0, 0, 0], size=(1000, 16)))

    if len(X) < MIN_SAMPLES:
        print(f"Warning: Only {len(X)} samples — consider capturing more baseline traffic (need >= {MIN_SAMPLES}).")
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Grid search params
    n_estimators_grid = [50, 100, 150, 200, 300, 400, 500]
    contamination_grid = [0.01, 0.03, 0.05, 0.08, 0.1, 0.12, 0.15, 0.2]
    max_samples_grid = ["auto", 0.5, 0.8, 1.0]

    best_score = float('-inf')
    best_params = None
    best_model = None

    print(f"Testing {len(n_estimators_grid) * len(contamination_grid) * len(max_samples_grid)} combinations in parallel...")

    def evaluate_params(n_est, cont, m_samp, X_sc, scaler):
        model = IsolationForest(
            n_estimators=n_est,
            contamination=cont,
            max_samples=m_samp,
            random_state=42,
            n_jobs=1 # Inner parallelization disabled to favor outer grid parallelization
        )
        model.fit(X_sc)
        
        correct_preds = 0
        normal_score = 0
        anomaly_scores = []
        
        for label, vec in SAMPLES.items():
            x = np.array([vec], dtype=float)
            x_sc = scaler.transform(x)
            pred = model.predict(x_sc)[0]
            score = model.score_samples(x_sc)[0] 
            
            if pred == EXPECTED_PREDS[label]:
                correct_preds += 1
            if label == 'Normal':
                normal_score = score
            else:
                anomaly_scores.append(score)

        avg_anomaly_score = sum(anomaly_scores) / len(anomaly_scores)
        margin = normal_score - avg_anomaly_score
        fitness = correct_preds * 1000 + margin
        return fitness, {'n_estimators': n_est, 'contamination': cont, 'max_samples': m_samp}, model

    results = Parallel(n_jobs=-1)(
        delayed(evaluate_params)(n_est, cont, m_samp, X_scaled, scaler)
        for n_est, cont, m_samp in product(n_estimators_grid, contamination_grid, max_samples_grid)
    )

    # Find best result
    best_fitness, best_params, best_model = max(results, key=lambda x: x[0])
    best_score = best_fitness

    print(f"\nOptimization Results:")
    print(f"=====================")
    print(f"Score Metric: {best_score:.4f} (Margin + Predefined Constraints)")
    print(f"Best n_estimators: {best_params['n_estimators']}")
    print(f"Best contamination: {best_params['contamination']}")
    print(f"Best max_samples: {best_params['max_samples']}")
    
    # Save model
    joblib.dump(best_model, OUTPUT_PATH)
    print(f"\nModel saved to {OUTPUT_PATH}")

    # Update yaml natively without stripping comments if possible, but safe_load drops comments.
    # However, since config is small and basic, writing dict back is acceptable.
    ml_cfg['model']['params']['n_estimators'] = best_params['n_estimators']
    ml_cfg['model']['params']['contamination'] = float(best_params['contamination'])
    ml_cfg['model']['params']['max_samples'] = best_params['max_samples'] if isinstance(best_params['max_samples'], str) else float(best_params['max_samples'])
    
    with open(CONFIG_PATH, 'w') as f:
        yaml.dump(ml_cfg, f, default_flow_style=False, sort_keys=False)
    
    print(f"Updated {CONFIG_PATH} with best parameters.")

if __name__ == '__main__':
    main()
