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
