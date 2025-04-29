import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detect import thread_and_run
from Log.logger import init_db
import os
from dotenv import load_dotenv

def main():
    load_dotenv() # Load .env variables
    init_db('VMMonitorDB') # Create database if necessary
    interface = os.getenv("NETWORK_INTERFACE") # Get network interface
    thread_and_run(interface) # Run the VM Monitoring function
    

if __name__ == "__main__":
    main()