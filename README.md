# DataCloak

Threat Detector API

🔒 Next-Gen Cybersecurity Anomaly Detection

Advanced Threat Detector API is a production-ready, AI-powered cybersecurity threat detection system. It continuously learns from incoming log events, detects anomalies using an unsupervised Isolation Forest model, and provides API endpoints for seamless integration into SIEMs, microservices, and enterprise security platforms.

## Features

#### API Key Authentication - Secure API access via X-API-KEY headers.

#### Persistent Logging - Stores cybersecurity events in a SQL database.

#### AI-Driven Anomaly Detection - Continuously retrains an Isolation Forest model to detect threats dynamically.

#### Modular & Scalable - Designed for SaaS deployment and enterprise security integrations.

#### Background Model Retraining - Learns continuously from incoming event logs.

#### SIEM & Microservices Ready - Easily integrates with existing cybersecurity infrastructure.


Installation & Setup

Install Dependencies

```
pip install flask sqlalchemy scikit-learn pandas
```

Set Up Environment Variables

```
export API_KEY="your_secret_api_key"
export DATABASE_URL="sqlite:///threat_logs.db"  # Change to a production DB if needed
export PORT=5000
```

Run the Service

```
python advanced_threat_detector.py
```

The API will be available at: http://localhost:5000


API Endpoints

Submit Log Entry

Endpoint: /api/submit_logMethod: POSTHeaders: { "X-API-KEY": "your_api_key" }

Payload:

```
{
  "ip_address": "192.168.1.100",
  "username": "jdoe",
  "event_type": "login_attempt",
  "event_value": 1.0
}
```

Response:
```
{
  "status": "success",
  "id": 123
}
```


Analyze Event for Anomalies

Endpoint: /api/analyzeMethod: POSTHeaders: { "X-API-KEY": "your_api_key" }

Payload:
```

{
  "ip_address": "192.168.1.101",
  "username": "hacker",
  "event_type": "login_attempt",
  "event_value": 5.0,
  "timestamp": "2025-02-05T12:34:56"
}
```

Response:

```
{
  "anomaly_score": -0.42,
  "prediction": "anomaly",
  "model_last_trained": "2025-02-05T12:30:00"
}
```

Check API & Model Status


Check API & Model Status

Endpoint: /api/statusMethod: GETHeaders: { "X-API-KEY": "your_api_key" }

Response:
```
{
  "service": "Advanced Threat Detector API",
  "model_trained": true,
  "last_training_time": "2025-02-05T12:30:00",
  "training_interval_sec": 60
}
```


# How It Works

#### Logs are submitted via /api/submit_log endpoint.

### Data is stored in the local/SQL database.

### Background AI model retrains every 60 seconds using Isolation Forest.

### Incoming events are analyzed for anomalies via /api/analyze.

### API provides anomaly scores and predictions (normal or anomaly).




