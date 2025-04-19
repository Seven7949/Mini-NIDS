# Mini-NIDS 🛡️  
A lightweight Python-based Network Intrusion Detection System (NIDS) with built-in alerting via Email and Discord.

## Features
- Real-time packet sniffing
- Port scan detection
- Traffic spam detection
- Email and Discord alerts
- Logging

## Requirements
- Python 3.7+
- Scapy
- yagmail
- requests

## Setup
1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/Mini-NIDS.git
    cd Mini-NIDS
    ```

2. Install dependencies:
    ```bash
    pip install scapy yagmail requests
    ```

3. Edit `nids.py` to fill in the **configuration section** with your:
    - Your email address and app password (for sending emails)
    - Receiver's email address
    - Your Discord webhook URL

4. Run the tool (you may need `sudo` privileges for packet sniffing):
    ```bash
    sudo python3 nids.py
    ```

> **Disclaimer:** This tool is for educational purposes. Use responsibly.

---

### 🎯 Next Steps to Add:

1. **Add a License (optional)**: You can add a license to let people know how they can use your code. For example, an MIT license.

To do that:
```bash
touch LICENSE

