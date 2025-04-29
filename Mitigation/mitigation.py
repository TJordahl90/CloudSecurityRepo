import subprocess
import docker

def block_ip(ip, interface=None):
    if interface:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-i", interface, "-s", ip, "-j", "DROP"])
    else:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

def restart_container(name):
    client = docker.from_env()
    container = client.containers.get(name)
    container.restart()

def cleanup_disk(path="/tmp"):
    subprocess.run(f"sudo rm -rf {path}/*", shell=True)
