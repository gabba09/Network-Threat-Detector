# Network Threat Detector
### Network Threat Detection Through PCAP File Analysis

## About the Project

Network Threat Detector is a Python-based cybersecurity project that analyzes PCAP/PCAPNG files to examine network traffic and identify potentially suspicious activities.

The project uses Scapy for packet inspection and performs protocol analysis, IP address analysis, port analysis, and basic network threat detection.

## Key Features

- PCAP/PCAPNG File Analysis
- TCP, UDP, ICMP, IP and ARP Packet Statistics
- Top Source and Destination IP Analysis
- Source and Destination Port Analysis
- TCP SYN Packet Detection
- Potential Port Scanning Detection
- Basic ARP Spoofing Detection

## Technologies Used

- Python
- Scapy
- TCP/IP
- PCAP/PCAPNG

## Installation

Clone the repository:

```bash
git clone https://github.com/USERNAME/network-threat-detector.git
```

Navigate to the project directory:

```bash
cd network-threat-detector
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Place your PCAP/PCAPNG file inside the `samples` directory.

Update the PCAP file path in the Python script:

```python
packets = rdpcap("samples/arp.pcapng")
```

Run the program:

```bash
python network_threat_detector.py
```

## Project Objective

To develop practical skills in network traffic analysis, packet inspection, and identification of potentially suspicious network activities through PCAP file analysis.

## Disclaimer

This project is intended for educational and cybersecurity research purposes. Detection results are preliminary indicators and should be verified through further investigation.

## Author

Developed as a student cybersecurity project.
