# Packet Analyzer

This project is a simple packet analyzer implemented in Python using the `scapy` and `tkinter` libraries. It can capture live network traffic, load packets from a `.pcap` file, analyze the captured packets, and detect potential anomalies in network traffic.

## Installation

To use this packet analyzer, you will need Python 3 and the following libraries:

- scapy
- tkinter

You can install `scapy` with `pip`:

```bash
pip install scapy
```
tkinter is included with Python, so you do not need to install it separately.

## Usage

To start the packet analyzer, run the Python file:

```bash
python packet_analyzer.py
```
The packet analyzer has the following features:

- Start Live Capture: Click this button to start capturing live network traffic. The captured packets will be displayed in the console.
- Print Statistics: Click this button to display statistics about the captured traffic, such as the most common source and destination IPs and the most common protocol.
- Check Anomalies: Click this button to check for potential anomalies in the captured traffic. An IP is considered an anomaly if it has sent more packets than a certain threshold.
- Load PCAP: Click this button to load packets from a .pcap file. The loaded packets will be analyzed and displayed in the console.
