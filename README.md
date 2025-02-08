# DataCloak

Threat Detector API

🔒 Next-Gen Cybersecurity Anomaly Detection

Advanced Threat Detector API is a production-ready, AI-powered cybersecurity threat detection system. It continuously learns from incoming log events, detects anomalies using an unsupervised Isolation Forest model, and provides API endpoints for seamless integration into SIEMs, microservices, and enterprise security platforms.

## Features

#### 🔥 API Key Authentication - Secure API access via X-API-KEY headers.

#### 🔥 Persistent Logging - Stores cybersecurity events in a SQL database.

#### 🔥 AI-Driven Anomaly Detection - Continuously retrains an Isolation Forest model to detect threats dynamically.

#### 🔥 Modular & Scalable - Designed for SaaS deployment and enterprise security integrations.

#### 🔥 Background Model Retraining - Learns continuously from incoming event logs.

#### 🔥 SIEM & Microservices Ready - Easily integrates with existing cybersecurity infrastructure.


#### – Log Ingestion & Persistence:
The script uses SQLAlchemy to define and persist three key database tables: one for raw threat logs, one for recording each model retraining event, and one for capturing anomaly detection events. This design provides a full audit trail of both system activity and model evolution.

#### Continuous Model Adaptation:
– Scheduled Retraining with APScheduler:
Instead of relying on ad hoc background threads, the script employs APScheduler to run the retraining job at configurable intervals. 

#☝️ Release Version 2.0 

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

License

MIT License - Feel free to use, modify, and distribute.
