# 🛡️ SentinelAI

### Intelligent Network Intrusion Detection & Risk Analysis System

SentinelAI is a Python-based network security monitoring project that combines **live network packet capture, feature extraction, machine-learning anomaly detection, risk scoring, and an explainable security-agent layer** in an interactive Streamlit dashboard.

The system captures network traffic from the local machine for a configurable time window, extracts traffic statistics, uses an **Isolation Forest** model to identify unusual behavior, converts the result into a **0–100 risk score**, and presents a security explanation and recommended action.

---

## ✨ Features

- 📡 **Live network traffic capture** using Scapy
- 📊 **Traffic statistics dashboard**
- 🌐 TCP/UDP protocol analysis
- ⬆️ Incoming/outgoing traffic analysis
- 🔗 Forward/backward packet analysis
- 🌍 Unique source and destination IP counts
- 🤖 **Isolation Forest anomaly detection**
- 📈 StandardScaler-based feature preprocessing
- 🎯 NORMAL / SUSPICIOUS prediction
- 🚨 0–100 security risk score
- 🧠 Explainable security-agent analysis
- 🛡️ Risk-based recommended actions
- 🔍 Complete live-feature inspection
- 📋 Final analysis summary
- 🖥️ Interactive Streamlit interface

---

## 🧠 How SentinelAI Works

```text
                    Local Computer
                         │
                         ▼
                ┌─────────────────┐
                │  Scapy Capture  │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Feature         │
                │ Extraction      │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ StandardScaler  │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Isolation Forest│
                │ Anomaly Model   │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ AI Prediction   │
                │ NORMAL /        │
                │ SUSPICIOUS      │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Risk Engine     │
                │ 0 - 100         │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Security Agent  │
                │ Explanation +   │
                │ Recommendation  │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Streamlit       │
                │ Dashboard       │
                └─────────────────┘
```

---

## 📊 Dashboard

The SentinelAI dashboard is divided into several sections.

### Live Traffic Statistics

Displays:

| Metric | Description |
|---|---|
| Total Packets | Number of IP packets observed during capture |
| Total Bytes | Total captured packet size |
| Packets / Second | Average packet rate |
| Bytes / Second | Average traffic rate |

### Protocol & Traffic Direction

Displays:

| Metric | Description |
|---|---|
| TCP Packets | Packets containing TCP traffic |
| UDP Packets | Packets containing UDP traffic |
| Incoming Packets | Packets received by the local machine |
| Outgoing Packets | Packets sent by the local machine |

### Connection Information

Displays:

| Metric | Description |
|---|---|
| Forward Packets | Traffic originating from the local machine |
| Backward Packets | Traffic arriving at the local machine |
| Unique Sources | Number of distinct source IP addresses |
| Unique Destinations | Number of distinct destination IP addresses |

### AI Detection Result

The model result is displayed as:

```text
Prediction
Risk Score
Risk Level
```

Example:

```text
Prediction: SUSPICIOUS
Risk Score: 60/100
Risk Level: MEDIUM
```

### Security Agent Analysis

The agent explains why the traffic was considered unusual and provides a recommended security action.

---

## ⏱️ What is Network Capture Duration?

The dashboard provides a **Network Capture Duration** slider.

For example:

```text
Capture Duration = 5 seconds
```

means SentinelAI listens to the local network interface for five seconds.

The computer's network connection is **not stopped**.

The application simply observes and analyzes packets during that period:

```text
Start Capture
      ↓
Capture Packets
      ↓
Wait for selected duration
      ↓
Stop Capture
      ↓
Extract Features
      ↓
Run AI Model
      ↓
Calculate Risk
      ↓
Display Results
```

A longer capture can collect more traffic, while a shorter capture provides a quicker analysis.

---

## 🤖 Machine Learning

SentinelAI uses the **Isolation Forest** algorithm for anomaly detection.

Isolation Forest is suitable for identifying observations that differ significantly from typical traffic patterns.

The model works with extracted network features such as:

```text
total_packets
total_bytes
packets_per_second
bytes_per_second
tcp_packets
udp_packets
incoming_packets
outgoing_packets
forward_packets
backward_packets
forward_bytes
backward_bytes
unique_sources
unique_destinations
```

The features are standardized using `StandardScaler` before being passed to the trained model.

### Anomaly Score

The dashboard also displays the Isolation Forest decision score.

A lower decision score generally indicates a more unusual observation.

> The anomaly score is a model decision score, not an attack probability.

---

## 🗂️ Project Structure

```text
SentinelAI/
│
├── app.py
├── requirements.txt
├── README.md
│
├── data/
│   └── dataset.csv
│
├── models/
│   ├── live_isolation_forest.joblib
│   └── live_scaler.joblib
│
└── src/
    ├── live_monitor.py
    ├── live_model.py
    ├── live_agent.py
    └── train_live_model.py
```

### File Responsibilities

#### `app.py`

Main Streamlit application.

Responsible for:

- Dashboard UI
- Capture controls
- Traffic metrics
- AI prediction
- Risk display
- Security alerts
- Agent explanation
- Recommended actions

#### `src/live_monitor.py`

Responsible for:

- Network packet capture
- Identifying local IP
- TCP/UDP counting
- Incoming/outgoing traffic
- Forward/backward traffic
- Source/destination analysis
- Live feature generation

#### `src/live_model.py`

Responsible for:

- Loading the trained model
- Loading the scaler
- Preparing live features
- Running anomaly prediction
- Returning the anomaly score

#### `src/live_agent.py`

Responsible for:

- Risk calculation
- Risk-level classification
- Explanation generation
- Recommended security actions

#### `src/train_live_model.py`

Responsible for:

- Preparing training data
- Training the Isolation Forest
- Training/saving the scaler
- Saving the trained model

---

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| Streamlit | Interactive dashboard |
| Scapy | Live packet capture |
| Pandas | Data processing |
| NumPy | Numerical operations |
| Scikit-learn | Machine learning |
| Isolation Forest | Anomaly detection |
| StandardScaler | Feature scaling |
| Joblib | Model persistence |
| VS Code | Development environment |
| Npcap | Windows packet-capture support |

---

# 🚀 Installation

## 1. Clone the Repository

```bash
git clone https://github.com/Nivedithakatta08/network-instrusion-detection-agent
cd SentinelAI
```

---

## 2. Create a Virtual Environment

### Windows

```bash
python -m venv venv
```

Activate it:

```bash
venv\Scripts\activate
```

### macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` does not exist, install the main packages with:

```bash
pip install streamlit pandas numpy scikit-learn joblib scapy matplotlib
```

---

## 4. Windows Npcap Setup

If you are running SentinelAI on Windows, install **Npcap** so Scapy can access network interfaces.

Npcap:

```text
https://npcap.com/
```

During installation, enabling WinPcap-compatible mode can help applications that expect the older WinPcap interface.

---

# 📁 Dataset

Place the training dataset inside the `data` directory:

```text
data/
└── dataset.csv
```

The exact dataset columns depend on the intrusion-detection dataset selected for the project.

To inspect the dataset:

```python
import pandas as pd

df = pd.read_csv("data/dataset.csv")

print(df.head())
print(df.columns.tolist())
print(df.shape)
```

To check missing values:

```python
print(df.isnull().sum())
```

The training pipeline should select the features required by the live model and ensure that the training feature order matches the feature order used during live prediction.

---

# 🧪 Train the Model

Run:

```bash
python src/train_live_model.py
```

After successful training, the following files should be available:

```text
models/
├── live_isolation_forest.joblib
└── live_scaler.joblib
```

These files are required by the live dashboard.

---

# ▶️ Run SentinelAI

Start Streamlit:

```bash
streamlit run app.py
```

Open the local URL shown by Streamlit, normally:

```text
http://localhost:8501
```

---

# 📡 Running Live Detection

1. Start the Streamlit application.
2. Choose the network capture duration.
3. Click **Analyze Live Traffic**.
4. SentinelAI captures packets for the selected duration.
5. Traffic features are extracted.
6. The trained scaler transforms the features.
7. Isolation Forest evaluates the observation.
8. A prediction is generated.
9. The risk engine calculates a risk score.
10. The security agent explains the result.
11. The dashboard displays the complete analysis.

---

# 🚨 Risk Levels

The application presents traffic using risk levels such as:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

The exact thresholds are controlled by the implementation in:

```text
src/live_agent.py
```

A risk level should be treated as an indicator for investigation rather than definitive proof of an attack.

---

# 🧪 Example Dashboard Output

Example:

```text
Live Traffic Statistics

Total Packets       113
Total Bytes         45,072
Packets / Second    22.60
Bytes / Second      9,014.40
```

```text
Protocol & Traffic Direction

TCP Packets         102
UDP Packets         11
Incoming Packets    35
Outgoing Packets    78
```

```text
Connection Information

Forward Packets       78
Backward Packets      35
Unique Sources        13
Unique Destinations   22
```

```text
AI Detection Result

Prediction: SUSPICIOUS
Risk Score: 60/100
Risk Level: MEDIUM
```

---

# 🔍 Feature Inspection

The dashboard includes:

```text
View All Live Network Features
```

This section allows users to inspect the feature values generated from the current network capture.

This is useful for:

- Debugging
- Model validation
- Demonstrating the ML pipeline
- Understanding network behavior
- Project presentations

---

# 🐛 Troubleshooting

## `ModuleNotFoundError`

Install the missing dependency:

```bash
pip install -r requirements.txt
```

---

## Model Not Found

If the dashboard reports:

```text
Live AI Model: Not Found
```

run:

```bash
python src/train_live_model.py
```

Then verify:

```text
models/live_isolation_forest.joblib
models/live_scaler.joblib
```

exist.

---

## Permission Denied During Packet Capture

On Windows, try:

1. Install Npcap.
2. Close the current Streamlit process.
3. Start VS Code as Administrator.
4. Activate the virtual environment.
5. Run:

```bash
streamlit run app.py
```

---

## No or Very Few Packets

Make sure network activity is occurring during the capture window.

For example:

- Open a website.
- Refresh a webpage.
- Use a network application.
- Generate normal network traffic.

---

# 🔐 Security & Privacy

SentinelAI is designed for authorized network monitoring and educational/research use.

Only capture or analyze traffic on systems and networks where you have permission.

The application should not be used to monitor networks without authorization.

---

# ⚠️ Limitations

Current limitations include:

- Live monitoring is based on the traffic visible to the local machine.
- A short capture window may not represent long-term network behavior.
- An anomaly is not necessarily a confirmed cyberattack.
- Model accuracy depends on the quality and relevance of training data.
- Network interfaces and packet visibility vary by operating system and configuration.
- Risk scores are application-level indicators rather than standardized security ratings.

---

# 🔮 Future Enhancements

Potential future improvements include:

- 📈 Real-time traffic graphs
- 📊 Historical traffic dashboards
- 🗃️ Database-backed event storage
- 🔔 Email/SMS security alerts
- 🌐 Threat-intelligence integration
- 🌍 IP geolocation
- 🔎 Port-level analysis
- 🧠 LLM-powered security explanations
- 📝 Automatic incident reports
- 👥 Multi-device monitoring
- 🔐 User authentication
- 📡 Network-interface selection
- 📚 Historical anomaly analysis
- 🎯 Attack-type classification
- 🚨 Continuous real-time monitoring

---

# 🎓 Project Objective

The objective of SentinelAI is to demonstrate an end-to-end intelligent network security pipeline:

```text
Dataset
   ↓
Data Preprocessing
   ↓
Machine Learning
   ↓
Model Training
   ↓
Live Packet Capture
   ↓
Feature Extraction
   ↓
Anomaly Detection
   ↓
Risk Scoring
   ↓
Security Agent
   ↓
Dashboard
```

The project demonstrates how machine learning can be combined with network monitoring and explainable security logic to assist with identifying unusual network behavior.

---

# 📜 Disclaimer

SentinelAI is an educational/research project and should not be treated as a production-grade intrusion prevention system.

AI predictions and risk scores are indicators and should be validated using additional security telemetry, logs, threat intelligence, and professional security tools.

Use the project only on systems and networks for which you have authorization.

---

# 👨‍💻 Authors

**Niveditha Katta, Meghana Kammari, Kokonda Sravya, Anupama Sharma**

GitHub: `https://github.com/Nivedithakatta08`

Project: `SentinelAI`

---


