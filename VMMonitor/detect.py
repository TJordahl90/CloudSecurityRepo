import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Mitigation')))
import pyshark
import psutil
from mitigation import block_ip, cleanup_disk
from Log.logger import log_event
import threading
import time
from collections import Counter

def monitor_icmp(interface):
    capture = pyshark.LiveCapture(interface=interface)
    hostIP = '192.168.50.220' # Dont want to block host ip
#    capture.sniff(packet_count=20)
    blockedIPs = set() # Dont want duplicates for efficiency

    for packet in capture.sniff_continuously(): # Continuously sniff to not limit the program 20 packets
        if hasattr(packet, 'icmp'):
            ip = packet.ip.src
            if(ip == hostIP): # Skip if the src is the host machine we dont care about outgoing pings
                continue

            with lock: # Lock the mutex to avoid race conditions
                sources[ip] += 1

#            print("ICMP Packet", f"Received from {ip}") # For testing purposes

            with lock: # Lock mutex
                if sources[ip] >= 5:
                    log_event("Mitigation", f"ICMP flood from {ip}")
#                    print("Mitigation", f"ICMP flood from {ip}") # For testing
                    if(ip not in blockedIPs): # If the ip is already blocked we do not need to block it again
                        block_ip(ip)
                        blockedIPs.add(ip) # Add newly blocked ips to the set if needed

def monitor_disk():
    while(True):
        time.sleep(10)
        usage = psutil.disk_usage('/')
        log_event("Disk", f"Disk usage: {usage.percent}%")
        print(f"Disk usage: {usage.percent}%")
        if usage.percent > 95:
            log_event("Mitigation", "Disk usage exceeded 95%")
            print("Mitigation", "Disk usage exceeded 95%")
            cleanup_disk("/tmp")

def thread_and_run(interface):
    global lock
    lock = threading.Lock()
    global sources
    sources = Counter()

    icmpThread = threading.Thread(target=monitor_icmp, args=(interface,))
    diskThread = threading.Thread(target=monitor_disk)
    icmpThread.start()
    diskThread.start()

    icmpThread.join()
    diskThread.join()
    #monitor_disk()