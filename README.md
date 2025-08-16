# 🛡️ Intrusion Detection and Prevention System (IDPS)

This project implements a **network-based Intrusion Detection and Prevention System (IDPS)** in Python.  
It monitors **network connections and system processes** in real time, and classifies suspicious behavior using a trained ML model.

---

## 🚀 Features
- 🌐 **Network Monitoring** – Detects suspicious TCP/UDP connections in real time.
- ⚙️ **Process Monitoring** – Tracks system processes and flags anomalies.
- 🤖 **Machine Learning Detection** – Uses a trained Random Forest model to classify malicious vs. benign activity.
- ⚡ **Real-time Alerts** – Displays alerts for suspicious connections/processes.
- 🔒 **Prevention Mode (Optional)** – Can block malicious processes or terminate risky connections.

---
**🧠 Machine Learning Model**

Algorithm: Random Forest Classifier
Model & Scaler: Saved using joblib in paths specified inside config.py

## 📂 Project Structure
idps_project/
│── config.py # Configuration (model path, thresholds, feature order)
│── model.py # Detector class (loads trained ML model + scaler)
│── detector.py # Anomaly detector logic
│── monitor.py # Network + process monitoring
│── idps.py # Main entry point (starts monitoring services)
│── requirements.txt # Python dependencies
│── README.md # Project documentation

## 🛠️ Installation
1. Clone the repository:
git clone [https://github.com/your-username/idps-project.git](https://github.com/RANIAZULFIQAR/Intrusion-Detection-and-Prevention-System.git)
cd idps-project

**(Optional but recommended) Create a virtual environment:**
python -m venv venv
source venv/bin/activate   # Linux / Mac
venv\Scripts\activate      # Windows

**Install dependencies:**
pip install -r requirements.txt

**⚡ Usage**
Run the IDPS with:
python idps.py

**🔑 Running the Project**
⚠️ The IDPS requires Administrator / root privileges to monitor and prevent system-level activities

The system will start monitoring:
Active network connections
Running processes
Alerts for suspicious activity will be displayed in the console.

**Using the CLI**
To run the network-based IDPS from your terminal:
# On Windows (run as Administrator)
python main.py --iface "Wi-Fi"

# On Linux/macOS (run with sudo)
sudo python3 main.py --iface wlan0

**⚠️ Disclaimer**

This project is for educational and research purposes only.
It is not a production-ready security sEnsure usage complies with copyright laws, data protection regulations, and cybersecurity ethics.
The author is not responsible for misuse of this software.olution.
Use responsibly in controlled environments.
Ensure usage complies with copyright laws, data protection regulations, and cybersecurity ethics.
The author is not responsible for misuse of this software.

**👩‍💻 Author**
- Rania Zulfiqar
- BS Computer Science — NUST
- GitHub:[ RANIAZULFIQAR](https://github.com/RANIAZULFIQAR)
