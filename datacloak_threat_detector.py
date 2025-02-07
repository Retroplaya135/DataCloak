#!/usr/bin/env python3\
import os\
import threading\
import time\
from datetime import datetime\
\
from flask import Flask, request, jsonify, abort\
from sqlalchemy import Column, Integer, String, DateTime, Float, create_engine\
from sqlalchemy.ext.declarative import declarative_base\
from sqlalchemy.orm import sessionmaker\
\
import pandas as pd\
from sklearn.ensemble import IsolationForest\
\
# --- CONFIGURATION & SETUP ---\
\
API_KEY = os.environ.get("API_KEY", "supersecret")  # simple API key mechanism\
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///threat_logs.db")\
TRAIN_INTERVAL = 60  # seconds\
\
app = Flask(__name__)\
Base = declarative_base()\
engine = create_engine(DATABASE_URL)\
SessionLocal = sessionmaker(bind=engine)\
\
# Global model object & lock for thread safety\
model_lock = threading.Lock()\
ai_model = None  # Will be an IsolationForest instance\
last_training_time = None\
\
# --- DATABASE MODEL ---\
\
class ThreatLog(Base):\
    __tablename__ = "threat_logs"\
    id = Column(Integer, primary_key=True, index=True)\
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)\
    ip_address = Column(String(50), nullable=False)\
    username = Column(String(100))\
    event_type = Column(String(50))   # e.g., "login_attempt", "file_access", etc.\
    event_value = Column(Float, default=0.0)  # numerical metric (e.g., duration, count)\
\
Base.metadata.create_all(bind=engine)\
\
# --- UTILITY FUNCTIONS ---\
\
def require_api_key(func):\
    def wrapper(*args, **kwargs):\
        key = request.headers.get("X-API-KEY")\
        if key != API_KEY:\
            abort(401, description="Unauthorized: Invalid API Key")\
        return func(*args, **kwargs)\
    wrapper.__name__ = func.__name__\
    return wrapper\
\
def get_training_data():\
    """Load data from DB and return as DataFrame with engineered features."""\
    session = SessionLocal()\
    try:\
        logs = session.query(ThreatLog).all()\
        # Build DataFrame: for demo, we encode ip_address and username as hash values\
        data = [\{\
            "timestamp": log.timestamp.timestamp(),\
            "ip_hash": hash(log.ip_address) % 1000,  # crude hash feature\
            "user_hash": hash(log.username or "") % 1000,\
            "event_value": log.event_value\
        \} for log in logs]\
        if not data:\
            return None\
        df = pd.DataFrame(data)\
        return df\
    finally:\
        session.close()\
\
def retrain_model():\
    """Background training of the IsolationForest model."""\
    global ai_model, last_training_time\
    while True:\
        df = get_training_data()\
        if df is not None and not df.empty:\
            features = df[["timestamp", "ip_hash", "user_hash", "event_value"]]\
            new_model = IsolationForest(contamination=0.05, random_state=42)\
            new_model.fit(features)\
            with model_lock:\
                ai_model = new_model\
                last_training_time = datetime.utcnow()\
            print(f"[\{datetime.utcnow()\}] Model retrained on \{len(features)\} records.")\
        else:\
            print(f"[\{datetime.utcnow()\}] No data available for training.")\
        time.sleep(TRAIN_INTERVAL)\
\
# Start background training thread\
trainer_thread = threading.Thread(target=retrain_model, daemon=True)\
trainer_thread.start()\
\
# --- API ENDPOINTS ---\
\
@app.route('/api/submit_log', methods=['POST'])\
@require_api_key\
def submit_log():\
    """\
    Submit a cybersecurity event log.\
    Expected JSON:\
    \{\
      "ip_address": "192.168.1.100",\
      "username": "jdoe",\
      "event_type": "login_attempt",\
      "event_value": 1.0\
    \}\
    """\
    data = request.get_json()\
    required = ["ip_address", "event_type"]\
    if not data or not all(k in data for k in required):\
        return jsonify(\{"error": "Missing required fields"\}), 400\
\
    new_log = ThreatLog(\
        ip_address=data["ip_address"],\
        username=data.get("username"),\
        event_type=data["event_type"],\
        event_value=float(data.get("event_value", 0.0))\
    )\
    session = SessionLocal()\
    try:\
        session.add(new_log)\
        session.commit()\
        return jsonify(\{"status": "success", "id": new_log.id\}), 201\
    finally:\
        session.close()\
\
@app.route('/api/analyze', methods=['POST'])\
@require_api_key\
def analyze_event():\
    """\
    Analyze a new event for anomaly score.\
    Expected JSON:\
    \{\
      "ip_address": "192.168.1.101",\
      "username": "hacker",\
      "event_type": "login_attempt",\
      "event_value": 5.0,\
      "timestamp": "2025-02-05T12:34:56"  # optional ISO timestamp; if missing, current time is used\
    \}\
    Returns an anomaly score (lower = normal, negative = anomaly)\
    """\
    data = request.get_json()\
    required = ["ip_address", "event_type"]\
    if not data or not all(k in data for k in required):\
        return jsonify(\{"error": "Missing required fields"\}), 400\
\
    ts = data.get("timestamp")\
    try:\
        ts_val = datetime.fromisoformat(ts) if ts else datetime.utcnow()\
    except Exception:\
        ts_val = datetime.utcnow()\
\
    # Feature engineering must match training: timestamp, ip_hash, user_hash, event_value\
    features = [[\
        ts_val.timestamp(),\
        hash(data["ip_address"]) % 1000,\
        hash(data.get("username", "")) % 1000,\
        float(data.get("event_value", 0.0))\
    ]]\
    \
    with model_lock:\
        current_model = ai_model\
    if current_model is None:\
        return jsonify(\{"error": "Model not yet trained, try again later."\}), 503\
    \
    # IsolationForest decision_function: higher means more normal; lower means anomalous.\
    score = current_model.decision_function(features)[0]\
    prediction = current_model.predict(features)[0]  # 1 for normal, -1 for anomaly\
    result = \{\
        "anomaly_score": score,\
        "prediction": "anomaly" if prediction == -1 else "normal",\
        "model_last_trained": last_training_time.isoformat() if last_training_time else "N/A"\
    \}\
    return jsonify(result)\
\
@app.route('/api/status', methods=['GET'])\
@require_api_key\
def status():\
    """Return service and model status."""\
    with model_lock:\
        trained = ai_model is not None\
    return jsonify(\{\
        "service": "Advanced Threat Detector API",\
        "model_trained": trained,\
        "last_training_time": last_training_time.isoformat() if last_training_time else "Never",\
        "training_interval_sec": TRAIN_INTERVAL\
    \})\
\
# --- ENTRY POINT ---\
\
if __name__ == '__main__':\
    port = int(os.environ.get('PORT', 5000))\
    print(f"Starting Advanced Threat Detector on port \{port\}")\
    app.run(host='0.0.0.0', port=port)\
}
