import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detect import monitor_udp, monitor_cpu
from Log.logger import init_db
import os
from dotenv import load_dotenv

def main():
    load_dotenv()
    init_db()
    interface = os.getenv("NETWORK_INTERFACE")
    container_name = os.getenv("CONTAINER_NAME")
    monitor_udp(interface)
    monitor_cpu(container_name)

if __name__ == "__main__":
    main()