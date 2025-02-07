#!/usr/bin/env python3
import os
import json
import time
import logging
from datetime import datetime

from flask import Flask, request, jsonify, abort
from sqlalchemy import Column, Integer, String, DateTime, Float, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import pandas as pd
from sklearn.ensemble import IsolationForest
from apscheduler.schedulers.background import BackgroundScheduler
import joblib

# --- CONFIG & LOGGING ---
API_KEY = os.environ.get("API_KEY", "supersecret")
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///threat_logs.db")
TRAIN_INTERVAL = int(os.environ.get("TRAIN_INTERVAL", 60))  # seconds
MODEL_FILE = os.environ.get("MODEL_FILE", "isolation_forest_model.pkl")
LOG_FILE = os.environ.get("LOG_FILE", "advanced_threat_detector.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.info("Service starting up...")

# --- FLASK & DB SETUP ---
app = Flask(__name__)
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

# Global model and thread-safety lock
from threading import Lock
model_lock = Lock()
ai_model = None
last_training_time = None

# --- DATABASE MODELS ---
class ThreatLog(Base):
    __tablename__ = "threat_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ip_address = Column(String(50), nullable=False)
    username = Column(String(100))
    event_type = Column(String(50))  # e.g., "login_attempt", etc.
    event_value = Column(Float, default=0.0)  # metric value

class ModelTrainingLog(Base):
    __tablename__ = "model_training_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    record_count = Column(Integer)
    details = Column(Text)  # additional info

class AnomalyDetectionLog(Base):
    __tablename__ = "anomaly_detection_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ip_address = Column(String(50))
    username = Column(String(100))
    event_type = Column(String(50))
    event_value = Column(Float)
    anomaly_score = Column(Float)
    prediction = Column(String(20))
    raw_event = Column(Text)  # JSON of the event

Base.metadata.create_all(bind=engine)
logging.info("Database tables ensured.")

# --- UTILITY FUNCTIONS ---
def require_api_key(func):
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-API-KEY")
        if key != API_KEY:
            abort(401, description="Unauthorized: Invalid API Key")
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def get_training_data():
    session = SessionLocal()
    try:
        logs = session.query(ThreatLog).all()
        data = [{
            "timestamp": log.timestamp.timestamp(),
            "ip_hash": hash(log.ip_address) % 1000,
            "user_hash": hash(log.username or "") % 1000,
            "event_value": log.event_value
        } for log in logs]
        if not data:
            return None
        return pd.DataFrame(data)
    except Exception as e:
        logging.error(f"Error in get_training_data: {e}")
        return None
    finally:
        session.close()

def save_model(model):
    try:
        joblib.dump(model, MODEL_FILE)
        logging.info("Model saved to disk.")
    except Exception as e:
        logging.error(f"Failed to save model: {e}")

def load_model():
    global ai_model, last_training_time
    if os.path.exists(MODEL_FILE):
        try:
            model = joblib.load(MODEL_FILE)
            with model_lock:
                ai_model = model
                last_training_time = datetime.utcnow()
            logging.info("Model loaded from disk.")
        except Exception as e:
            logging.error(f"Failed to load model: {e}")

def log_model_training(record_count, details=""):
    session = SessionLocal()
    try:
        log_entry = ModelTrainingLog(
            record_count=record_count,
            details=details
        )
        session.add(log_entry)
        session.commit()
        logging.info(f"Training log recorded: {record_count} records; {details}")
    except Exception as e:
        logging.error(f"Error logging training event: {e}")
    finally:
        session.close()

def log_detection_event(event, score, prediction):
    session = SessionLocal()
    try:
        log_entry = AnomalyDetectionLog(
            ip_address=event.get("ip_address"),
            username=event.get("username"),
            event_type=event.get("event_type"),
            event_value=float(event.get("event_value", 0.0)),
            anomaly_score=score,
            prediction="anomaly" if prediction == -1 else "normal",
            raw_event=json.dumps(event)
        )
        session.add(log_entry)
        session.commit()
        logging.info(f"Detection logged: {event.get('ip_address')} score={score:.3f}")
    except Exception as e:
        logging.error(f"Error logging detection event: {e}")
    finally:
        session.close()

def retrain_model():
    global ai_model, last_training_time
    df = get_training_data()
    if df is not None and not df.empty:
        features = df[["timestamp", "ip_hash", "user_hash", "event_value"]]
        new_model = IsolationForest(contamination=0.05, random_state=42)
        new_model.fit(features)
        with model_lock:
            ai_model = new_model
            last_training_time = datetime.utcnow()
        save_model(new_model)
        detail = f"Trained on {len(features)} records; features: {list(features.columns)}"
        log_model_training(len(features), detail)
        logging.info(f"Model retrained on {len(features)} records.")
    else:
        logging.info("No data available for training.")

# --- SCHEDULER SETUP ---
scheduler = BackgroundScheduler()
scheduler.add_job(retrain_model, 'interval', seconds=TRAIN_INTERVAL, id="model_trainer")
scheduler.start()
logging.info("Background scheduler started for model retraining.")
load_model()  # attempt to load existing model on startup

# --- API ENDPOINTS ---
@app.route('/api/submit_log', methods=['POST'])
@require_api_key
def submit_log():
    """
    Submit a cybersecurity event log.
    Expected JSON:
    {
      "ip_address": "192.168.1.100",
      "username": "jdoe",
      "event_type": "login_attempt",
      "event_value": 1.0
    }
    """
    data = request.get_json()
    if not data or not all(k in data for k in ["ip_address", "event_type"]):
        return jsonify({"error": "Missing required fields"}), 400

    new_log = ThreatLog(
        ip_address=data["ip_address"],
        username=data.get("username"),
        event_type=data["event_type"],
        event_value=float(data.get("event_value", 0.0))
    )
    session = SessionLocal()
    try:
        session.add(new_log)
        session.commit()
        logging.debug(f"New event logged: {data}")
        return jsonify({"status": "success", "id": new_log.id}), 201
    except Exception as e:
        logging.error(f"Error in submit_log: {e}")
        session.rollback()
        return jsonify({"error": "Database error"}), 500
    finally:
        session.close()

@app.route('/api/analyze', methods=['POST'])
@require_api_key
def analyze_event():
    """
    Analyze an event for anomaly score.
    Expected JSON:
    {
      "ip_address": "192.168.1.101",
      "username": "hacker",
      "event_type": "login_attempt",
      "event_value": 5.0,
      "timestamp": "2025-02-05T12:34:56"  # optional ISO timestamp
    }
    """
    data = request.get_json()
    if not data or not all(k in data for k in ["ip_address", "event_type"]):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        ts_val = datetime.fromisoformat(data.get("timestamp")) if data.get("timestamp") else datetime.utcnow()
    except Exception:
        ts_val = datetime.utcnow()

    features = [[
        ts_val.timestamp(),
        hash(data["ip_address"]) % 1000,
        hash(data.get("username", "")) % 1000,
        float(data.get("event_value", 0.0))
    ]]
    with model_lock:
        current_model = ai_model
    if current_model is None:
        return jsonify({"error": "Model not yet trained, try again later."}), 503

    score = current_model.decision_function(features)[0]
    prediction = current_model.predict(features)[0]
    result = {
        "anomaly_score": score,
        "prediction": "anomaly" if prediction == -1 else "normal",
        "model_last_trained": last_training_time.isoformat() if last_training_time else "N/A"
    }
    log_detection_event(data, score, prediction)
    return jsonify(result)

@app.route('/api/status', methods=['GET'])
@require_api_key
def status():
    with model_lock:
        trained = ai_model is not None
    return jsonify({
        "service": "Advanced Threat Detector API v3.0",
        "model_trained": trained,
        "last_training_time": last_training_time.isoformat() if last_training_time else "Never",
        "training_interval_sec": TRAIN_INTERVAL
    })

@app.route('/api/training_logs', methods=['GET'])
@require_api_key
def training_logs():
    """Retrieve recent model training logs."""
    session = SessionLocal()
    try:
        logs = session.query(ModelTrainingLog).order_by(ModelTrainingLog.timestamp.desc()).limit(20).all()
        data = [{
            "timestamp": log.timestamp.isoformat(),
            "record_count": log.record_count,
            "details": log.details
        } for log in logs]
        return jsonify(data)
    finally:
        session.close()

@app.route('/api/detection_logs', methods=['GET'])
@require_api_key
def detection_logs():
    """Retrieve recent anomaly detection logs."""
    session = SessionLocal()
    try:
        logs = session.query(AnomalyDetectionLog).order_by(AnomalyDetectionLog.timestamp.desc()).limit(20).all()
        data = [{
            "timestamp": log.timestamp.isoformat(),
            "ip_address": log.ip_address,
            "username": log.username,
            "event_type": log.event_type,
            "event_value": log.event_value,
            "anomaly_score": log.anomaly_score,
            "prediction": log.prediction,
            "raw_event": json.loads(log.raw_event)
        } for log in logs]
        return jsonify(data)
    finally:
        session.close()

# --- ENTRY POINT ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logging.info(f"Starting Advanced Threat Detector API v3.0 on port {port}")
    try:
        app.run(host='0.0.0.0', port=port)
    except Exception as e:
        logging.error(f"Failed to start Flask server: {e}")
