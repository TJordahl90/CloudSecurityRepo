import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detect import thread_and_run
from Log.logger import init_db
import os
from dotenv import load_dotenv

def main():
    load_dotenv()
    init_db('ContainerDB')
    #interface = os.getenv("NETWORK_INTERFACE")
    interface = 'docker0'
    container_name = os.getenv("CONTAINER_NAME")
    containerIP = os.getenv('CONTAINER_IP')
    thread_and_run(interface, container_name, containerIP)

if __name__ == "__main__":
    main()