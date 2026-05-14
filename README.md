# DNSoverHttpsDomainNameSniffer

DNS over HTTPS Domain Name Sniffer

Welcome to the official page of my **DNS over HTTPS Domain Name Sniffer**.

---

## Key Features

### DNS and TLS Domain Name Display
My sniffer not only detects traditional DNS queries but also displays TLS domain names (SNI), making it possible to identify domains even when using DNS over HTTPS.

### Modern Web Interface
A sleek and intuitive web interface ensures ease of use. With live updates via WebSockets, you stay informed in real time.

### PCAP File Support
Load and analyze existing PCAP files directly within the software to gain detailed insights into recorded network activities.

### Compatible with Network Monitoring Setups
To capture complete network traffic, a switch with a monitor port is required and must be properly configured.

Tested on:

- Debian
- Ubuntu
- Kali Linux
- Fedora (64-bit)
- Raspberry Pi 4 / Raspberry Pi 5 (ARM64)
- Nvidia Jetson platforms
- Windows
---

## Technical Notes

### Administrator Privileges Required
Root or administrator rights are necessary to run the software.

### Security and Precision
Designed for maximum transparency and control over network data, the software ensures reliable performance.

Thanks to TCP reassembly, WiFi traffic arriving at the switch is accurately reconstructed and displayed, ensuring comprehensive and reliable network analysis across all traffic sources.

---

## Try it Now!

Experience a new level of network monitoring — precise, user-friendly, and powerful.

Download the DNS over HTTPS Sniffer today and take full control of your network analysis.

---

## Linux Binary for x86

```bash
unzip dnsTlsSniffer812Linux.zip
chmod +x ./dnsTlsSniffer812Linux
sudo ./dnsTlsSniffer812Linux
