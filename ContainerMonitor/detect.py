import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pyshark
import psutil
from mitigate import block_ip, restart_container
from Log.logger import log_event

def monitor_udp(interface):
    capture = pyshark.LiveCapture(interface=interface)
    sources = []
    capture.sniff(packet_count=20)
    for packet in capture:
        if hasattr(packet, 'udp'):
            ip = packet.ip.src
            sources.append(ip)
            log_event("UDP Packet", f"Received from {ip}")
    for ip in set(sources):
        if sources.count(ip) >= 5:
            log_event("Mitigation", f"UDP flood from {ip}")
            block_ip(ip)

def monitor_cpu(container_name):
    usage = psutil.cpu_percent(interval=5)
    log_event("CPU", f"CPU usage: {usage}%")
    if usage > 90:
        log_event("Mitigation", "CPU usage exceeded 90%")
        restart_container(container_name)