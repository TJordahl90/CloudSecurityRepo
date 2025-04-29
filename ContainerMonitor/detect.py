import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Mitigation')))
import threading
import pyshark
import psutil
from mitigation import block_ip, restart_container
from Log.logger import log_event
from collections import Counter
import docker
import time

def monitor_udp(interface, containerIP):
    capture = pyshark.LiveCapture(interface=interface, display_filter = 'udp')
    blockedIPs = set()
    sources = Counter()
    #capture.sniff(packet_count=20)
    for packet in capture.sniff_continuously(): # Sniff continuously
        #print(packet)
        if('UDP' in packet and 'IP' in packet): # Make sure the packet is udp and has an ip 
            #print(packet.layers)
            if(packet.ip.dst == containerIP): # Make sure the destination of the packet is the container
                with lock:
                    ip = packet.ip.src
                    sources[ip] += 1
                    #print("UDP Packet", f"Received from {ip}")
                    log_event('ContainerDB', "UDP Packet", f"Received from {ip}") # Log event
                if(sources[ip] > 1000 and ip not in blockedIPs):
                    with lock:
                        print("Mitigation", f"UDP flood from {ip}")
                        log_event('ContainerDB', "Mitigation", f"UDP flood from {ip}") # Log event
                        block_ip(ip, interface) # Block the IP
                        blockedIPs.add(ip) # Add the newly blocked IP to the blockedIPs set


def monitor_cpu(container_name):
    client = docker.from_env() # Get client
    container = client.containers.get(container_name) # Get container

    while True:
        stats = container.stats(stream=False) # Get container stats

        # Calculate CPU usage from the system and container
        cpuDelta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - stats["precpu_stats"]["cpu_usage"]["total_usage"]
        systemDelta = stats["cpu_stats"]["system_cpu_usage"] - stats["precpu_stats"]["system_cpu_usage"]
        perCPU = stats["cpu_stats"]["cpu_usage"].get("percpu_usage", None) # Get CPU stats

        print(f'Cpu Delta: {cpuDelta}')
        print(f'System Delta: {systemDelta}')

        # Calculate cpu usage statsa
        if systemDelta > 0:
            perCPU = stats["cpu_stats"]["cpu_usage"].get("percpu_usage", [])
            cpu_count = len(perCPU) if perCPU else 1
            cpuUsage = (cpuDelta / systemDelta) * cpu_count * 100.0
        else:
            cpuUsage = 0

        print(f'Cpu Usage: {cpuUsage}')

        if cpuUsage > 89: # If very high CPU usage
            print("Mitigation", "CPU usage exceeded 89%")
            log_event('ContainerDB', "Mitigation", "CPU usage exceeded 89%") # Log event
            restart_container(container_name) # Restart the container

def thread_and_run(interface, container_name, containerIP):
    global lock # Create a global mutex lock
    lock = threading.Lock()

    # Thread the application
    udpThread = threading.Thread(target=monitor_udp, args=(interface, containerIP))
    cpuThread = threading.Thread(target=monitor_cpu, args=(container_name, ))

    udpThread.start()
    cpuThread.start()

    try:
        udpThread.join()
        cpuThread.join()
    except KeyboardInterrupt:
        print('\nExiting main thread, program killed')
        sys.exit(0)