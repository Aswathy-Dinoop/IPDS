# Machine Learning Based IDPS using CNN

A complete Network Intrusion Detection and Prevention System built with Python, Flask, Scapy, and TensorFlow/Keras.

## 📁 Project Structure
- `data/`: Contains dataset files.
- `model/`: Stores trained CNN model (`cnn_model.h5`) and encoders.
- `static/`: CSS, JS, and images for the dashboard.
- `templates/`: HTML files for the dashboard.
- `app.py`: Main Flask Web Application.
- `sniffer.py`: Real-time packet capture and blocking engine.
- `train_model.py`: Script to train the CNN model.
- `preprocessing.py`: Data handling and processing.
- `database.py`: SQLite logging system.

## 🚀 Setup Instructions

### 1. Requirements
Ensure you have Python 3.8+ installed.
Install dependencies:
```bash
pip install -r requirements.txt
```
**CRITICAL FOR WINDOWS:**
- Install [Npcap](https://npcap.com/#download).
- During installation, check **"Install Npcap in WinPcap API-compatible Mode"**.

### 2. Dataset (NSL-KDD)
The project comes with a generator for dummy data so you can run it immediately.
For the **REAL** project output:
1. Download **NSL-KDD** dataset from [University of New Brunswick](https://www.unb.ca/cic/datasets/nsl.html) or [Kaggle](https://www.kaggle.com/datasets/hassan06/nslkdd).
2. Place `KDDTrain+.txt` inside the `data/` folder.

### 3. Execution Steps
**Step 1: Train the Model**
Run this once to build the CNN model.
```bash
python train_model.py
```
*Output: Saves `model/cnn_model.h5` and `static/accuracy_graph.png`*

**Step 2: Start the IDPS Dashboard**
```bash
python app.py
```
*Output: Running on http://127.0.0.1:5000*

**Step 3: Activate Sniffer**
- Open the dashboard in your browser.
- Click **"ACTIVATE DEFENSE SYSTEM"**.
- The system will start monitoring traffic.
- Generate traffic (e.g., ping valid or invalid IPs) to see logs.

## 🛡 Features
- **CNN Deep Learning Model**: Classifies traffic as Normal or Attack.
- **Real-Time Sniffer**: Captures packets using Scapy.
- **Automatic Blocking**: Blocks malicious IPs using Windows Firewall (`netsh`) or Linux (`iptables`).
- **Live Dashboard**: Visualizes threats in real-time.

## 📚 Viva Explanation Points
1. **Why CNN?** CNNs are excellent at feature extraction. While 1D-CNN is usually for sequences, we use it here to extract spatial correlations between packet features.
2. **Preprocessing**: We map categorical data (TCP, UDP) to numbers and scale numerical values (Bytes) to 0-1 range for the Neural Network.
3. **Prevention**: The system keeps a list of malicious IPs and adds firewall rules dynamically to drop their future packets.
4. **Scapy**: Used for raw socket access to read incoming packets at the kernel level.

## ⚠️ Admin Privileges
To block IPs and sniff packets, you must run the terminal/IDE as **Administrator**.
