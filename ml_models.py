import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pickle
import os
from database import insert_model_metrics, get_active_model, set_active_model, insert_activity_log


MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
DATASETS_DIR = os.path.join(os.path.dirname(__file__), '..', 'datasets', 'processed')
if not os.path.exists(MODELS_DIR):
    os.makedirs(MODELS_DIR)


class IDSModels:
    """Machine learning models for intrusion detection."""
    
    def __init__(self):
        self.models = {}
        self.scaler = StandardScaler()
        self.load_or_create_models()
    
    def load_or_create_models(self):
        """Load existing models or create new ones."""
        model_files = {
            'random_forest': os.path.join(MODELS_DIR, 'random_forest.pkl'),
            'svm': os.path.join(MODELS_DIR, 'svm.pkl'),
            'isolation_forest': os.path.join(MODELS_DIR, 'isolation_forest.pkl'),
            'gradient_boosting': os.path.join(MODELS_DIR, 'gradient_boosting.pkl'),
        }
        
        for model_name, path in model_files.items():
            if os.path.exists(path):
                try:
                    with open(path, 'rb') as f:
                        self.models[model_name] = pickle.load(f)
                except:
                    self.models[model_name] = None
            else:
                self.models[model_name] = None
    
    def save_model(self, model_name, model):
        """Save a trained model to disk."""
        path = os.path.join(MODELS_DIR, f'{model_name}.pkl')
        with open(path, 'wb') as f:
            pickle.dump(model, f)
    
    @staticmethod
    def load_real_dataset():
        """Load and preprocess the CIC-IDS2017 dataset."""
        try:
            possible_paths = [
                os.path.join(os.path.dirname(__file__), '..', 'datasets', 'CIC-IDS2017', 'cic_ids2017_balanced.csv')
            ]

            df = None
            for path in possible_paths:
                if os.path.exists(path):
                    try:
                        temp = pd.read_csv(path)
                        if df is None:
                            df = temp
                        else:
                            df = pd.concat([df, temp], ignore_index=True)
                    except Exception:
                        continue

            if df is None or df.empty:
                print("Real dataset not found, falling back to synthetic data")
                return None, None

            df.columns = [c.strip() for c in df.columns]
            label_col = next((c for c in df.columns if c.strip().lower() in ['label', 'attack_type', 'traffic_type', 'target', 'class']), None)
            if label_col is None:
                print("Real dataset missing label column, falling back to synthetic data")
                return None, None

            # Exclude features that are directly derived from or highly predictive of the label
            feature_candidates = [
                'port', 'bytes_sent', 'bytes_received', 'cpu_usage', 'memory_usage',
                'network_load', 'response_time', 'total_bytes', 'bytes_diff',
                'total_resource_usage'
            ]
            selected_features = [c for c in feature_candidates if c in df.columns]
            if not selected_features:
                # Fall back to numeric features but exclude known leaky columns
                excluded = {'severity', 'bytes_ratio', 'load_per_byte', 'cpu_memory_ratio', 'network_efficiency'}
                selected_features = [
                    c for c in df.select_dtypes(include=[np.number]).columns
                    if c != label_col and c not in excluded
                ]

            if not selected_features:
                print("No numeric features found in real dataset, falling back to synthetic data")
                return None, None

            df = df.dropna(subset=[label_col] + selected_features)
            if df.empty:
                print("Real dataset has no complete rows, falling back to synthetic data")
                return None, None

            X = df[selected_features].apply(pd.to_numeric, errors='coerce').fillna(0).to_numpy()
            y_raw = df[label_col].astype(str).str.strip().str.lower()
            y = np.array([
                0 if v in ['benign', 'normal traffic', 'normal', 'no attack', 'benign traffic'] else 1
                for v in y_raw
            ])

            if len(X) == 0 or len(X) != len(y):
                print("No usable samples from real dataset, falling back to synthetic data")
                return None, None

            print(f"Loaded {len(X)} samples from real dataset using features: {selected_features}")
            print(f"Attack samples: {int(sum(y))}, Benign samples: {len(y) - int(sum(y))}")
            return X, y
        except Exception as e:
            print(f"Error loading real dataset: {e}")
            return None, None

    def generate_training_data(self, samples=1000):
        """Generate synthetic training data when real dataset is unavailable."""
        X = []
        y = []

        for _ in range(int(samples * 0.85)):
            src_port = np.random.randint(1024, 65535) / 65535.0
            dst_port = np.random.randint(1, 1024) / 65535.0
            protocol = np.random.randint(0, 4) / 3.0
            packet_size = np.random.normal(500, 100) / 1500.0
            packet_size = np.clip(packet_size, 0, 1)
            X.append([src_port, dst_port, protocol, packet_size])
            y.append(0)

        for _ in range(int(samples * 0.15)):
            src_port = np.random.randint(1024, 65535) / 65535.0
            dst_port = np.random.choice([53, 445, 3389]) / 65535.0
            protocol = np.random.randint(0, 4) / 3.0
            packet_size = np.random.uniform(0.8, 1.0)
            X.append([src_port, dst_port, protocol, packet_size])
            y.append(1)

        return np.array(X), np.array(y)

    def train_all_models(self, samples=1000):
        """Train all IDS models using cross-validation and return evaluation metrics."""
        # Try to load real dataset first
        X, y = self.load_real_dataset()

        if X is None or len(X) == 0:
            print("Using synthetic data for training")
            X, y = self.generate_training_data(samples)
        else:
            print("Using real CIC-IDS2017 dataset for training")
            # Use a subset if too large
            if len(X) > samples:
                indices = np.random.choice(len(X), samples, replace=False)
                X, y = X[indices], y[indices]

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        results = {}

        # Cross-validation setup
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

        # Random Forest
        print("Training Random Forest with cross-validation...")
        rf_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
        
        # Cross-validation scores first
        rf_accuracy = cross_val_score(rf_model, X_scaled, y, cv=cv, scoring='accuracy')
        rf_precision = cross_val_score(rf_model, X_scaled, y, cv=cv, scoring='precision_macro')
        rf_recall = cross_val_score(rf_model, X_scaled, y, cv=cv, scoring='recall_macro')
        rf_f1 = cross_val_score(rf_model, X_scaled, y, cv=cv, scoring='f1_macro')

        results['random_forest'] = {
            'accuracy': float(rf_accuracy.mean()),
            'precision': float(rf_precision.mean()),
            'recall': float(rf_recall.mean()),
            'f1_score': float(rf_f1.mean())
        }
        
        # Now train on full dataset for deployment
        rf_model.fit(X_scaled, y)
        self.models['random_forest'] = rf_model
        self.save_model('random_forest', rf_model)
        svm_model = SVC(probability=True, random_state=42, class_weight='balanced')
        svm_model.fit(X_scaled, y)  # Train on full dataset for deployment
        self.models['svm'] = svm_model
        self.save_model('svm', svm_model)

        svm_accuracy = cross_val_score(svm_model, X_scaled, y, cv=cv, scoring='accuracy')
        svm_precision = cross_val_score(svm_model, X_scaled, y, cv=cv, scoring='precision_macro')
        svm_recall = cross_val_score(svm_model, X_scaled, y, cv=cv, scoring='recall_macro')
        svm_f1 = cross_val_score(svm_model, X_scaled, y, cv=cv, scoring='f1_macro')

        results['svm'] = {
            'accuracy': float(svm_accuracy.mean()),
            'precision': float(svm_precision.mean()),
            'recall': float(svm_recall.mean()),
            'f1_score': float(svm_f1.mean())
        }

        # Now train on full dataset for deployment
        svm_model.fit(X_scaled, y)
        self.models['svm'] = svm_model
        self.save_model('svm', svm_model)

        # Gradient Boosting
        print("Training Gradient Boosting with cross-validation...")
        gb_model = GradientBoostingClassifier(n_estimators=100, random_state=42)
        
        gb_accuracy = cross_val_score(gb_model, X_scaled, y, cv=cv, scoring='accuracy')
        gb_precision = cross_val_score(gb_model, X_scaled, y, cv=cv, scoring='precision_macro')
        gb_recall = cross_val_score(gb_model, X_scaled, y, cv=cv, scoring='recall_macro')
        gb_f1 = cross_val_score(gb_model, X_scaled, y, cv=cv, scoring='f1_macro')

        results['gradient_boosting'] = {
            'accuracy': float(gb_accuracy.mean()),
            'precision': float(gb_precision.mean()),
            'recall': float(gb_recall.mean()),
            'f1_score': float(gb_f1.mean())
        }
        
        # Now train on full dataset for deployment
        gb_model.fit(X_scaled, y)
        self.models['gradient_boosting'] = gb_model
        self.save_model('gradient_boosting', gb_model)

        # Isolation Forest (Unsupervised) - no cross-validation needed for unsupervised
        print("Training Isolation Forest...")
        contamination = min(0.5, max(0.01, sum(y) / len(y)))  # Estimate contamination from labels, cap at 0.5
        if_model = IsolationForest(contamination=contamination, random_state=42)
        if_model.fit(X_scaled)
        self.models['isolation_forest'] = if_model
        self.save_model('isolation_forest', if_model)

        # For isolation forest, use a simple train/test split for evaluation
        X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42, stratify=y)
        y_pred_if = if_model.predict(X_test)
        y_pred_if = (y_pred_if == -1).astype(int)

        results['isolation_forest'] = {
            'accuracy': float(accuracy_score(y_test, y_pred_if)),
            'precision': float(precision_score(y_test, y_pred_if, zero_division=0)),
            'recall': float(recall_score(y_test, y_pred_if, zero_division=0)),
            'f1_score': float(f1_score(y_test, y_pred_if, zero_division=0))
        }

        # Store metrics in database
        for model_name, metrics in results.items():
            insert_model_metrics(
                model_name=model_name,
                accuracy=metrics['accuracy'],
                precision=metrics['precision'],
                recall=metrics['recall'],
                f1_score=metrics['f1_score'],
                is_active=0
            )
            print(f"{model_name}: F1-Score = {metrics['f1_score']:.4f}, Accuracy = {metrics['accuracy']:.4f}")

        # Activate the best performing model by F1 score
        best_model_name = max(results.items(), key=lambda item: item[1]['f1_score'])[0]
        set_active_model(best_model_name)
        insert_activity_log('MODEL_TRAINING', f'Completed training of {len(results)} models with cross-validation and activated best model {best_model_name}')
        return results
    
    def predict(self, features, model_name='random_forest', min_confidence=0.6):
        """
        Predict if traffic is anomalous using a specific model.
        Returns (is_anomaly, confidence)
        """
        if model_name not in self.models or self.models[model_name] is None:
            return 0, 0.0

        features_scaled = self.scaler.transform([features])
        model = self.models[model_name]

        if model_name == 'isolation_forest':
            prediction = model.predict(features_scaled)[0]
            is_anomaly = 1 if prediction == -1 else 0
            confidence = abs(model.score_samples(features_scaled)[0])
        else:
            prediction = model.predict(features_scaled)[0]
            probabilities = model.predict_proba(features_scaled)[0]
            is_anomaly = int(prediction)
            confidence = max(probabilities)

        return is_anomaly, float(confidence)

    def predict_batch(self, features_list, model_name='random_forest'):
        """Predict anomalies for a batch of features."""
        if model_name not in self.models or self.models[model_name] is None:
            return []
        
        features_scaled = self.scaler.transform(features_list)
        model = self.models[model_name]
        
        predictions = model.predict(features_scaled)
        
        if model_name == 'isolation_forest':
            results = [
                (1 if p == -1 else 0, abs(model.score_samples([f])[0]))
                for p, f in zip(predictions, features_scaled)
            ]
        else:
            probabilities = model.predict_proba(features_scaled)
            results = [
                (int(p), float(max(prob)))
                for p, prob in zip(predictions, probabilities)
            ]
        
        return results
    
    def get_ensemble_prediction(self, features):
        """
        Get ensemble prediction using all available models.
        Returns voting result and average confidence.
        """
        predictions = {}
        confidences = {}
        
        for model_name in self.models.keys():
            anomaly, conf = self.predict(features, model_name)
            predictions[model_name] = anomaly
            confidences[model_name] = conf
        
        # Voting
        vote = sum(predictions.values())
        is_anomaly = 1 if vote >= 2 else 0  # Majority vote
        avg_confidence = sum(confidences.values()) / len(confidences) if confidences else 0
        
        return is_anomaly, avg_confidence, predictions, confidences
    
    def get_model_comparison(self):
        """Get comparison of all trained models."""
        from database import get_latest_model_metrics
        models = get_latest_model_metrics()
        
        comparison = []
        for model in models:
            comparison.append({
                'name': model.get('model_name'),
                'accuracy': model.get('accuracy'),
                'precision': model.get('precision'),
                'recall': model.get('recall'),
                'f1_score': model.get('f1_score'),
                'timestamp': model.get('timestamp'),
                'id': model.get('id')
            })
        
        return comparison


# Global models instance
ids_models = None


def get_ids_models():
    """Get or create global models instance."""
    global ids_models
    if ids_models is None:
        ids_models = IDSModels()
    return ids_models
