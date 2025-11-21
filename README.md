# AnomalyM  
Machine-Learning–Driven Network Flow Anomaly Detection

AnomalyM is a lightweight network anomaly detection engine designed to process PCAP files, extract network flows, compute statistical and behavioral features, and detect suspicious activity using both heuristic rules and a machine-learning Isolation Forest model.  
It is a fully modular command-line tool that supports IPv4, IPv6, TCP, UDP, and ICMP flows.

---

## Features

### ✓ Flow-Based Packet Analysis
AnomalyM converts raw packets into flow-level summaries using:
- Source/Destination IP
- Source/Destination ports
- Protocol identification
- Byte counts
- Packet counts
- SYN/ACK metrics
- Shannon entropy of raw payloads

### ✓ Heuristic Detection Engine
Built-in rules can detect:
- SYN floods
- High entropy exfiltration patterns
- Suspicious port behavior
- Abnormal traffic bursts (optional depending on configuration)

### ✓ Machine Learning Detection
Using an Isolation Forest model, AnomalyM evaluates each network flow and assigns:
- An anomaly score
- Anomaly classification based on a configurable threshold

### ✓ Clean JSON Reporting
Results are exported in a structured JSON report containing both heuristic and ML findings.

---

## Project Structure

AnomalyM/
│
├── src/
│ ├── cli.py # Command-line interface
│ ├── engineering.py # Flow extraction & feature engineering
│ ├── packet_loader.py # PCAP loading with raw packet support
│ └── analyzers/
│ ├── heuristics.py # Heuristic rule-based detector
│ ├── ml_model.py # IsolationForest scoring logic
│ └── init.py
│
├── models/
│ └── isolation_forest.joblib # Machine learning model (generated after training)
│
├── scripts/
│ └── train_isolation_forest.py
│
└── README.md



---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/youruser/AnomalyM
cd AnomalyM


Create and Activate a Virtual Environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

3. Install Dependencies

The project uses pyshark, scikit-learn, and joblib.

pip install -r requirements.txt

Training the Machine Learning Model

Before running anomaly detection, you must train an Isolation Forest model using a baseline PCAP (normal traffic).

Example:

python -m scripts.train_isolation_forest baseline.pcap \
    --model-path models/isolation_forest.joblib \
    --max-packets 20000


This script:

Loads packets

Converts them into flows using the feature engineering module

Trains an Isolation Forest model

Saves the model into models/isolation_forest.joblib

If the model is missing, ML-based anomaly detection will not run.

Running the Analyzer

Use the CLI to process a PCAP and generate a JSON report:

python -m src.cli sample.pcap --output report.json --max-packets 500
