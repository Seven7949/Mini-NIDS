from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime
import logging
import yagmail
import requests

# ====== CONFIG SECTION ======
EMAIL_SENDER = "your_email@gmail.com"
EMAIL_PASSWORD = "your_app_password"  # use app password, not Gmail password
EMAIL_RECEIVER = "receiver_email@gmail.com"
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/your_webhook_here"
PACKET_THRESHOLD = 20
PORT_SCAN_THRESHOLD = 10

# ====== INIT SETUP ======
ip_packet_counter = defaultdict(int)
port_scan_tracker = defaultdict(set)
alerted_ips = set()

# Logging Setup
logging.basicConfig(filename="alerts.log", level=logging.INFO)

# ====== ALERT FUNCTIONS ======
def send_email_alert(ip, reason):
    try:
        yag = yagmail.SMTP(EMAIL_SENDER, EMAIL_PASSWORD)
        subject = f"⚠️ Intrusion Alert from {ip}"
        body = f"Suspicious activity detected.\nIP: {ip}\nReason: {reason}"
        yag.send(EMAIL_RECEIVER, subject, body)
        print(f"📧 Email sent for {ip}")
    except Exception as e:
        print(f"Email failed: {e}")

def send_discord_alert(ip, reason):
    try:
        message = {
            "content": f"🚨 **Alert:** Suspicious activity from `{ip}`\n**Reason:** {reason}\n🕒 `{datetime.now()}`"
        }
        requests.post(DISCORD_WEBHOOK_URL, json=message)
        print(f"💬 Discord alert sent for {ip}")
    except Exception as e:
        print(f"Discord webhook failed: {e}")

def log_alert(ip, reason):
    entry = f"[{datetime.now()}] ALERT: {ip} - {reason}"
    logging.info(entry)
    print(entry)

# ====== DETECTION FUNCTIONS ======
def detect_packet_spam(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ip_packet_counter[src_ip] += 1

        if ip_packet_counter[src_ip] > PACKET_THRESHOLD and src_ip not in alerted_ips:
            reason = f"High traffic volume: {ip_packet_counter[src_ip]} packets"
            alert_ip(src_ip, reason)

def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        if packet[TCP].flags == 'S':
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            port_scan_tracker[src_ip].add(dst_port)

            if len(port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD and src_ip not in alerted_ips:
                reason = f"Port scan detected on {len(port_scan_tracker[src_ip])} ports"
                alert_ip(src_ip, reason)

def alert_ip(ip, reason):
    log_alert(ip, reason)
    send_email_alert(ip, reason)
    send_discord_alert(ip, reason)
    alerted_ips.add(ip)

# ====== MAIN FUNCTION ======
def start_sniffing():
    print("👀 NIDS Started... Press Ctrl+C to stop.")
    sniff(prn=lambda pkt: (detect_packet_spam(pkt), detect_port_scan(pkt)), store=0)

# ====== START ======
if __name__ == "__main__":
    start_sniffing()
