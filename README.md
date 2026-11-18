# Network Threat Detector 

## About the Project

This is a Python project I made to learn more about network traffic analysis and basic cybersecurity.

I used **Scapy** to read and analyze PCAP/PCAPNG files. The main goal of this project is to understand how network packets work and identify some activities that could be suspicious.

The program analyzes different types of packets, checks source and destination IP addresses, looks at commonly used ports, and performs a few basic security checks.

## What This Project Does

### 1. Packet Analysis
- Counts the total number of packets.
- Identifies IP, TCP, UDP, ICMP, and ARP packets.
- Calculates the percentage of each protocol.

### 2. IP Address Analysis
- Finds the top 5 source IP addresses.
- Finds the top 5 destination IP addresses.
- Counts how many packets are sent and received by each IP.

### 3. Port Analysis
- Extracts source and destination ports from TCP and UDP packets.
- Finds the top 5 most frequently used source ports.
- Finds the top 5 most frequently used destination ports.

### 4. Basic Security Checks
- Counts TCP SYN packets that may indicate scanning activity.
- Checks for possible port scanning by tracking how many different destination ports a source IP accesses on the same destination IP.
- Checks for possible ARP spoofing by finding IP addresses associated with different MAC addresses.

## Tools & Technologies

- Python
- Scapy
- Collections (Counter)
- PCAP / PCAPNG files

## Project Structure

```text
Network-Threat-Detector/
│
├── samples/
│   ├── arp.pcapng
│   ├── demo.pcapng
│   └── port.pcap
│
├── network_threat_detector.py
├── README.md
├── requirements.txt
└── .gitignore
```

## Sample PCAP Files

I have added three sample packet capture files in the `samples` folder so that the program can be tested with different network traffic captures.

- `arp.pcapng`
- `demo.pcapng`
- `port.pcap`

## How to Run the Project

**Step 1: Clone the repository**

```bash
git clone https://github.com/gabba09/Network-Threat-Detector.git
```

**Step 2: Open the project folder**

```bash
cd Network-Threat-Detector
```

**Step 3: Install the required library**

```bash
pip install -r requirements.txt
```

**Step 4: Run the Python file**

```bash
python network_threat_detector.py
```

## Changing the PCAP File

By default, the program reads `arp.pcapng` from the samples folder.

```python
packets = rdpcap("samples/arp.pcapng")
```

If you want to analyze another file, you can simply change its name:

```python
packets = rdpcap("samples/demo.pcapng")
```

Or:

```python
packets = rdpcap("samples/port.pcap")
```

## What I Learned

While working on this project, I learned:

- How to read PCAP files using Scapy.
- How to identify different network protocols.
- How source and destination IP addresses work.
- How TCP and UDP ports are used in network communication.
- How to use Python's Counter to find frequently occurring values.
- How basic port scanning detection works.
- How ARP spoofing can be identified through IP and MAC address mappings.

## Future Improvements

I would like to improve this project by adding:

- Real-time packet capturing.
- Better port scanning detection.
- More accurate ARP spoofing detection.
- Graphs to visualize network traffic.
- Saving detected alerts in a separate log file.
- An option to select PCAP files without changing the code.

## Disclaimer

This project is made for learning and educational purposes. It is a basic network traffic analysis project and its alerts do not necessarily confirm an actual attack.

Please analyze only network traffic that you own or have permission to inspect.

## Author

**gabba09**

GitHub: https://github.com/gabba09
