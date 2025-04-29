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
    sources = Counter()
#    capture.sniff(packet_count=20)
    blockedIPs = set() # Dont want duplicates for efficiency

    for packet in capture.sniff_continuously(): # Continuously sniff to not limit the program 20 packets
        if hasattr(packet, 'icmp'):
            ip = packet.ip.src
            if(ip == hostIP): # Skip if the src is the host machine we dont care about outgoing pings
                continue

            #print("ICMP Packet", f"Received from {ip}") # For testing purposes

            with lock: # Lock the mutex to avoid race conditions
                sources[ip] += 1

                if sources[ip] >= 1000 and ip not in blockedIPs:
                    log_event('VMMonitorDB', "Mitigation", f"ICMP flood from {ip}")
                    print("Mitigation", f"ICMP flood from {ip}") # For testing

                    block_ip(ip)
                    blockedIPs.add(ip) # Add newly blocked ips to the set if needed

def monitor_disk():
    while(True):
        time.sleep(10) # Sleep
        usage = psutil.disk_usage('/tmp') # Check for disk usage from /tmp

        log_event('VMMonitorDB', "Disk", f"Disk usage: {usage.percent}%") # Log disk usage
        print(f"Disk usage: {usage.percent}%")

        if usage.percent > 95: # If the disk usage is unusually high
            log_event('VMMonitorDB', "Mitigation", "Disk usage exceeded 95%") # Log it
            print("Mitigation", "Disk usage exceeded 95%")
            cleanup_disk("/tmp") # Clean temp file

def thread_and_run(interface):
    global lock # Create a global mutex lock
    lock = threading.Lock()

    # Thread the application
    icmpThread = threading.Thread(target=monitor_icmp, args=(interface,))
    diskThread = threading.Thread(target=monitor_disk)
    icmpThread.start()
    diskThread.start()

    try:
        icmpThread.join()
        diskThread.join()
    except KeyboardInterrupt:
        print("\nExiting main thread, program killed")
        sys.exit(0)