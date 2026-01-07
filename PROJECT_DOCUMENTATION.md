# Machine Learning Based Network Intrusion Detection System (NIDS)
## Project Documentation for University Submission

### 1. Project Overview
**Title:** Network Intrusion Detection and Prevention System using Convolutional Neural Networks (CNN).

**Description:**
This project is a comprehensive Network security solution designed to detect and prevent malicious network activity in real-time. Unlike traditional signature-based firewalls that can only detect known threats, this system uses **Deep Learning (AI)** to analyze network traffic patterns and identify anomalies (zero-day attacks) such as Denial of Service (DoS) attacks, Port Scans, and Probes.

The system features a **live web dashboard** that displays threat statistics, active blocks, and allows administrators to monitor network health visually.

---

### 2. How to Run the Project

**Prerequisites:**
- Python 3.8+
- Administrator/Root privileges (required for network sniffing and blocking).

**Step-by-Step Execution:**

1.  **Install Dependencies:**
    Open a terminal in the project directory and run:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Train the AI Model (One-time setup):**
    Before the system can detect anything, it needs to learn. This script processes the NSL-KDD dataset and trains the CNN.
    ```bash
    python train_model.py
    ```
    *Output: Generates `model/cnn_model.h5` and an accuracy graph.*

3.  **Start the IDPS System (Dashboard & Sniffer):**
    Run the main application. This starts the Web UI and prepares the background sniffer.
    ```bash
    python app.py
    ```
    *Open your browser to: `http://127.0.0.1:5000`*
    *Click "ACTIVATE DEFENSE SYSTEM" on the dashboard.*

4.  **Simulate Attacks (Testing):**
    To demonstrate the project works, open a **separate** terminal window and run:
    ```bash
    python attack_simulation.py
    ```
    *Select Option 1 (DoS) or 2 (Port Scan). watch the Dashboard update in real-time!*

---

### 3. Tools & Technologies Used

We chose a modern stack to ensure performance, scalability, and ease of demonstration.

| Tool / Library | Purpose | Justification |
| :--- | :--- | :--- |
| **Python** | Core Language | Dominant language in AI/ML and Cybersecurity; vast library support. |
| **TensorFlow / Keras** | Machine Learning Framework | Industry-standard for building Deep Learning models (CNNs). |
| **Flask** | Web Backend | Lightweight and fast; allows us to easily serve a real-time Dashboard to the user. |
| **Scapy / Socket** | Network Interaction | **Scapy** is used for powerful packet manipulation and sniffing. **Sockets** are used for robust attack simulation. |
| **SQLite** | Database | Serverless, zero-configuration database perfect for storing attack logs locally. |
| **Pandas & NumPy** | Data Processing | Essential for handling the complex NSL-KDD dataset arrays and matrices. |

---

### 4. Algorithm Used: 1D Convolutional Neural Network (CNN)

While CNNs are famously used for Image Processing (2D), this project utilizes a **1D CNN**.

**Architecture Details:**
1.  **Input Layer**: Accepts an array of 41 features (derived from the NSL-KDD dataset standard) representing a single network connection.
2.  **Convolutional Layers (Conv1D)**:
    -   These layers slide over the input data to detect local patterns and correlations between features.
    -   *Example:* It might learn that a high `src_bytes` count combined with a specific `dst_host_count` is a strong indicator of an attack.
3.  **Pooling Layers (MaxPooling)**: Reduces the dimensionality, keeping only the most important features and making the model faster.
4.  **Dropout Layers**: Randomly ignores neurons during training to prevent "overfitting" (memorizing the data instead of learning).
5.  **Dense (Fully Connected) Layers**: The final classification layers that interpret the features and decide: **0 (Normal)** or **1 (Attack)**.

---

### 5. Critical Question: Why CNN instead of Random Forest?

This is a common question for defense. Here is the technical justification:

**1. Automated Feature Extraction:**
*   **Random Forest (RF)** relies heavily on "Hand-crafted Features". If the input data isn't perfectly processed by a human expert, RF fails.
*   **CNN** excels at "Representation Learning". It automatically learns the best features from the raw data. In network traffic, relationships between features are often complex and non-linear; CNNs capture these hidden dependencies better than tree-based models.

**2. Sequential Pattern Recognition:**
*   Network traffic is inherently sequential usage. 1D CNNs are specifically designed to process sequential data, making them more natural for spotting patterns that span across different parts of a packet header or flow.

**3. Generalization & Scalability:**
*   Deep Learning models (CNN) scale better with more data. As we add more attack signatures to the dataset, a CNN continues to improve, whereas Random Forest performance often "plateaus" (stops getting better) after a certain point.

**4. Modernity & Research Value:**
*   Moving beyond "Classical ML" (like Decision Trees/RF) to "Deep Learning" (CNN/RNN) demonstrates a higher level of technical sophistication appropriate for a final year university project.

---

### 6. Project Features (Summary for Presentation)
*   **Real-time Detection**: Identifies malicious packets as they arrive.
*   **Active Defense**: Can automatically command the Firewall to block malicious IPs.
*   **Visual Dashboard**: Provides an easy-to-understand interface for non-technical users.
*   **Simulation Suite**: Includes a built-in tool to generate safe attacks for demonstration purposes.
