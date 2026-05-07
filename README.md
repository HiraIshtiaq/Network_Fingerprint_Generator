# Network Fingerprint Generator & Website Behavior Profiler

An interactive web-based tool that captures live website traffic, analyzes network packets, and generates behavioral fingerprints using Scapy and Flask.

---

## 📌 Overview

The Network Fingerprint Generator captures traffic when a website is accessed and extracts useful networking features such as:

- Protocol distribution
- Packet sizes
- DNS queries
- Total traffic volume
- Unique destination IPs
- Traffic behavior patterns

The extracted data is converted into a structured network fingerprint and visualized using interactive charts.

---

## ✨ Features

- 🌐 Capture live website traffic
- 📦 Analyze packets using Scapy
- 📊 Generate protocol distribution charts
- 📈 Visualize traffic behavior
- 🔎 Extract DNS queries and IPs
- 🧠 Rule-based traffic classification
- ⚡ Flask REST API backend
- 💻 Clean and interactive UI

---

## 🛠️ Tech Stack

### Backend
- Python
- Flask
- Scapy

### Frontend
- HTML
- CSS
- JavaScript

### Visualization
- Chart.js

---

## 🚀 Getting Started

### 🔧 Installation

```bash
git clone https://github.com/HiraIshtiaq/Network_Fingerprint_Generator.git

cd Network_Fingerprint_Generator

pip install -r requirements.txt
```

---

### ▶️ Run the Project

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

---

## 📊 How It Works

1. User enters a website URL  
2. Flask backend triggers packet capture  
3. Scapy captures live network traffic  
4. Features are extracted from packets  
5. Fingerprint JSON is generated  
6. Website behavior is classified  
7. Results and charts are displayed  

---

## 🧠 Traffic Classification

The system labels website behavior as:

- Streaming
- Static Content
- API-Heavy
- Unknown

---

## 🎓 Educational Value

This project is useful for:

- Networking students
- Cybersecurity beginners
- Packet analysis practice
- Understanding real-world traffic behavior
- Learning Scapy and Flask integration

Visualization makes network analysis easier to understand compared to raw packet dumps.

---

## ⚠️ Requirements

For Windows packet capture:

- Install **Npcap**
- Enable **WinPcap Compatibility Mode**

Download:  
https://npcap.com

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository  
2. Create a new branch  
3. Make your changes  
4. Submit a Pull Request  

---

## ⭐ Show Your Support

If you like this project:

- ⭐ Star the repository
- 🍴 Fork it
- 📢 Share it with others

---

## 👩‍💻 Author

**Hira Ishtiaq**

GitHub:  
https://github.com/HiraIshtiaq
