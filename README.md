# Packet Sniffer

## Overview

This project is a simple packet sniffer program that captures and analyzes network packets. It is designed for educational purposes to help understand network protocols and packet structures.

## Features

- Capture packets on a specified network interface
- Display URL and username and passwords for basic HTTP websites

## Requirements

- Python 3.x
- `scapy` library

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/andymartinez1/Packet-Sniffer.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Packet-Sniffer
   ```

## Usage

1. Specify the network interface to capture packets on (e.g., `wlp0s20f3` on line 44).

2. Run the packet sniffer:
   ```bash
   sudo python3 packet_sniffer.py
   ```
3. Use in conjunction with the previous [Network scanner](https://github.com/andymartinez1/Network-Scanner) and [ARP Spoofer](https://github.com/andymartinez1/ARP-Spoofer) projects for packet sniffing on specific devices.
