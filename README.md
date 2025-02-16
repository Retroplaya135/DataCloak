# DataCloak

Threat Detector API

🔒 Next-Gen Cybersecurity Anomaly Detection

Advanced Threat Detector API is a production-ready, AI-powered cybersecurity threat detection system. It continuously learns from incoming log events, detects anomalies using an unsupervised Isolation Forest model, and provides API endpoints for seamless integration into SIEMs, microservices, and enterprise security platforms.

## Ststem Overview

```
+-----------------------+
|   Advanced Threat    |
|    Detector API      |
+-----------------------+
        |
        v
+------------------------+
|    API Endpoints       |
|    (Flask API)         |
+------------------------+
        |
        v
+-------------------------+
| SQL Database (Logs &    |
| Model Training Data)    |
+-------------------------+
        |
        v
+-------------------------+
|  AI Model (Isolation   |
|  Forest for Anomalies) |
+-------------------------+
```

## Features

#### 🔥 API Key Authentication - Secure API access via X-API-KEY headers.

#### 🔥 Persistent Logging - Stores cybersecurity events in a SQL database.

#### 🔥 AI-Driven Anomaly Detection - Continuously retrains an Isolation Forest model to detect threats dynamically.

#### 🔥 Modular & Scalable - Designed for SaaS deployment and enterprise security integrations.

#### 🔥 Background Model Retraining - Learns continuously from incoming event logs.

#### 🔥 SIEM & Microservices Ready - Easily integrates with existing cybersecurity infrastructure.


```
                       +----------------------+
                       |     API Client       |
                       +----------------------+
                                |
               +----------------+----------------+
               |                                 |
         POST /api/submit_log              POST /api/analyze
               |                                 |
               v                                 v
+-------------------------------+       +-------------------------------+
|         Flask API             |       |         Flask API             |
| (Log Submission & Ingestion)  |       | (Real-time Analysis Endpoint) |
+-------------------------------+       +-------------------------------+
               |                                 |
               |                                 |  (Transforms incoming event
               |                                 |   into numeric features)
               v                                 v
+-------------------------------+       +-------------------------------+
|      ThreatLog Table          |       |    Feature Engineering        |
|   (SQLAlchemy ORM Storage)    |       |         (pandas)              |
+-------------------------------+       +-------------------------------+
               |                                 |
               +-----------+        +------------+
                           |        |
                           |        v
                           |  +-------------------------------+
                           |  | IsolationForest Model         |
                           |  | (scikit‑learn for anomaly      |
                           |  |   detection)                  |
                           |  +-------------------------------+
                           |                |
                           |                | Model Scoring &
                           |                | Prediction
                           |                v
                           |  +-------------------------------+
                           |  | AnomalyDetectionLogs          |
                           |  | (Logs each detection event)   |
                           |  +-------------------------------+
                           |
                           |   (Data Aggregation for Training)
                           v
+-----------------------------------------------------+
|            Data Aggregation & Feature Extraction    |
|                (get_training_data using pandas)     |
+-----------------------------------------------------+
                           |
                           v
+-----------------------------------------------------+
|          IsolationForest Model Training             |
|   (Model retraining using aggregated features)      |
|   - Triggered by APScheduler (Background Scheduler) |
+-----------------------------------------------------+
                           |
                           | Save/Load via joblib
                           v
+-----------------------------------------------------+
|                 Model Persistence                   |
|        (ModelTrainingLogs & joblib storage)         |
+-----------------------------------------------------+
                           ^
                           |
             +-------------------------------+
             |  Background Scheduler         |
             |  (APScheduler periodically    |
             |   triggers retraining)        |
             +-------------------------------+

```

------ Added in Version 2.0 --------

#### – Log Ingestion & Persistence:
The script uses SQLAlchemy to define and persist three key database tables: one for raw threat logs, one for recording each model retraining event, and one for capturing anomaly detection events. This design provides a full audit trail of both system activity and model evolution.

#### Continuous Model Adaptation:
– Scheduled Retraining with APScheduler:
Instead of relying on ad hoc background threads, the script employs APScheduler to run the retraining job at configurable intervals. 

# API Flow

```
+----------------------+
|    API Client       |
| (SIEM / Microservices)|
+----------------------+
        |
        v
+-------------------------------+
|        Flask API              |
|  (Threat Log & Analysis)      |
+-------------------------------+
        |                 |
        |                 |
        v                 v
+----------------+  +----------------+
|   SQL Logs     |  |  Isolation     |
| (Event Storage)|  |  Forest Model  |
+----------------+  +----------------+
        |
        v
+-----------------------------+
|  Model Training & Retraining |
+-----------------------------+
```

#☝️ Release Version 2.0 

Additional endpoints (/api/training_logs and /api/detection_logs) allow administrators to retrieve recent training and detection events.

### Improved Background Training & API Endpoints:

Background model retraining using a dedicated thread.
Introduced API key authentication to secure endpoints.
Added endpoints for submitting logs (/api/submit_log) and analyzing events (/api/analyze).

### Model Persistence:
Integrated model saving and loading using joblib so that the trained Isolation Forest can be reused across restarts.
Initial Change Logging:
Logged key events (like new log submissions and training events) using Python’s logging module.

### Robust Scheduling:
Replaced simple threading with APScheduler for more robust and configurable background retraining.
Detailed Change Logging & Audit Trails:
Created dedicated database tables for both model training logs and anomaly detection logs.
Enhanced structured logging to file with detailed messages (including timestamps, record counts, and error handling).

#### Model Persistence & Resilience:
– joblib Integration:
By saving the trained model to disk and reloading it on startup, the solution minimizes downtime and avoids retraining from scratch after every restart. 

#### Advanced Logging & Traceability:
– Structured Python Logging:
Detailed logging is set up both to a file (for system audits) and into database tables (for operational analytics).

#### Security via API Key Enforcement:
– Endpoint Protection:
All API endpoints are secured with a simple API key mechanism, ensuring that only authorized clients can submit logs or request model status.

Admin Endpoints:
Added endpoints (/api/training_logs and /api/detection_logs) to retrieve a full changelog of model training events and detection events, offering transparency and a “moat” by tracking every change.


# Database Structure

```
+-------------------------------+
|         ThreatLog Table       |
|-------------------------------|
| id  | ip_address | username   |
|-------------------------------|
| 101 | 192.168.1.1| admin      |
| 102 | 10.0.0.2   | user123    |
+-------------------------------+

+----------------------------------+
|  AnomalyDetectionLogs Table     |
|----------------------------------|
| id  | event_id | anomaly_score  |
|----------------------------------|
| 201 | 101      |  -0.42         |
| 202 | 102      |  0.80          |
+----------------------------------+

+--------------------------------------+
|  ModelTrainingLogs Table            |
|--------------------------------------|
| id  | last_training_time             |
|--------------------------------------|
| 301 | 2025-02-05T12:30:00            |
+--------------------------------------+
```

# Installation & Setup

### Install Dependencies


### V1 main branch
```
pip install flask sqlalchemy scikit-learn pandas
```
### V2
```
pip install flask sqlalchemy pandas scikit-learn apscheduler joblib
```

#### Set Up Environment Variables

```
export API_KEY="your_secret_api_key"
export DATABASE_URL="sqlite:///threat_logs.db"  # Change to a production DB if needed
export PORT=5000
```

#### Run the Service

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

#  Model Training & API Lifecycle

```
+------------------------------------------------------+
|               Event Log Submission                  |
+------------------------------------------------------+
        |
        v
+-----------------------------+
|  Store Event in SQL         |
+-----------------------------+
        |
        v
+-----------------------------+
|  Feature Engineering        |
+-----------------------------+
        |
        v
+-----------------------------+
|  Isolation Forest Model     |
|  (Anomaly Detection)        |
+-----------------------------+
        |
        v
+-----------------------------+
|  API Response (Score)       |
+-----------------------------+

+------------------------------------------------------+
|               Model Retraining (APScheduler)        |
+------------------------------------------------------+
        |
        v
+-----------------------------+
| Aggregate New Training Data |
+-----------------------------+
        |
        v
+-----------------------------+
| Retrain Isolation Forest    |
+-----------------------------+
        |
        v
+-----------------------------+
| Save Model (joblib)         |
+-----------------------------+
```

# How It Works

#### Logs are submitted via /api/submit_log endpoint.

### Data is stored in the local/SQL database.

### Background AI model retrains every 60 seconds using Isolation Forest.

### Incoming events are analyzed for anomalies via /api/analyze.

### API provides anomaly scores and predictions (normal or anomaly).


# AI Model (Isolation Forest)

### Why Isolation Forest?

### Unsupervised learning: No labeled data required.

### Fast anomaly detection: Works well with cybersecurity event logs.

### Continuously retrains: Learns from real-world attack patterns.

# Feature Engineering

### Converts ip_address and username into hash-based features.

### Uses event timestamps and numerical values for learning.

### Detects deviations in behavior dynamically.


# SaaS & Monetization Potential

### Monetization Strategy

### Per API Call Pricing: Charge per /api/analyze request.

### Enterprise Licensing: Offer integration with corporate SIEMs.

### Freemium Model: Free basic API access, paid premium features.

# Security & Scalability

### API key authentication ensures secure access.

### Modular architecture allows deployment in microservices.

### Can be scaled via Kubernetes, Docker, or serverless platforms.

# Deployment & Security Architecture

+-------------------------------------------------+
|             Secure API Access                   |
|-------------------------------------------------|
| 🔒 API Key Authentication (X-API-KEY)           |
| 🔒 Logging of all API Calls                     |
| 🔒 Structured Logging for Traceability         |
+-------------------------------------------------+

+--------------------------------------------------+
|          Deployment Options                      |
|--------------------------------------------------|
| 🔹 Local Flask App                               |
| 🔹 Docker Deployment                            |
| 🔹 Kubernetes Deployment                        |
| 🔹 Cloud (AWS, GCP, Azure)                      |
+--------------------------------------------------+


Deployment

Deploy on Cloud (Example: AWS, GCP, Azure)

```
git clone https://github.com/yourusername/advanced-threat-detector.git
cd advanced-threat-detector
pip install -r requirements.txt
export API_KEY="your_secret_api_key"
export DATABASE_URL="sqlite:///threat_logs.db"
python advanced_threat_detector.py
```

# Deploy with Docker

### Create a Dockerfile:

```
FROM python:3.9
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
ENV API_KEY=your_secret_api_key
ENV DATABASE_URL=sqlite:///threat_logs.db
CMD ["python", "advanced_threat_detector.py"]
```

### Build and run the container:

```
docker build -t threat-detector .
docker run -p 5000:5000 -e API_KEY=your_secret_api_key threat-detector

```

# Deploy with Kubernetes

### Create a deployment.yaml:

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: threat-detector
spec:
  replicas: 2
  selector:
    matchLabels:
      app: threat-detector
  template:
    metadata:
      labels:
        app: threat-detector
    spec:
      containers:
      - name: detector
        image: your-dockerhub/threat-detector:latest
        env:
        - name: API_KEY
          value: "your_secret_api_key"
        ports:
        - containerPort: 5000
```

# Apply the deployment:

```
kubectl apply -f deployment.yaml
```

Libraries used:

Minimal Library Descriptions

#### Flask:
Lightweight web framework for REST API endpoints.
#### SQLAlchemy:
ORM for defining models and interacting with the database.
#### pandas:
Data manipulation and feature engineering (DataFrame operations).
#### scikit‑learn:
Machine learning library; here, the IsolationForest algorithm is used for anomaly detection.
scikit‑learn Site
#### APScheduler:
Schedules background tasks (periodic retraining jobs).
#### joblib:
Model serialization (saving and loading the trained model).


License

MIT License - Feel free to use, modify, and distribute.
