DDOS Mitigation Project - Group 1 - Trent Jordahl, Alessio Russolillo, Orion Vialpando

This repo contains a VM and Container-based attack detection and mitigation system using Python.

The following is how to setup the environment, and run the programs.
Setting up the Environment:
    1. Navigate to the CloudSecurityRepo directory
    2. Create a python virtual environment using "python3 -m venv venv"
    3. Activate the virtual environment using "source venv/bin/activate"
    4. Install dependencies using "pip3 install -r requirements.txt"
    5. Make sure you create your .env file with the correct information (Shown in video demonstration)

Running VM Monitor:
    ***Note that you must change the hostIP variable in the monitor_icmp function to reflect your host IP address***
    1. Navigate to the VMMonitor directory
    2. Run using "sudo -E "$(which python3)" "monitor.py""
    3. You are now free to test the VMMonitor functions as you please

Running Container Monitor:
    ***Please note that this will not work if you do not currently have a docker virtual environment currently running***
    1. Navigate to the ContainerMonitor directory
    2. Run using "sudo -E "$(which python3)" "monitor.py""
    3. You are now free to test the ContainerMonitor functions as you please.
    Here is the python script I used in the demonstration for the CPU Burn attack:
        python3 -c "import multiprocessing; [multiprocessing.Process(target=lambda: [x**2 for x in iter(int, 1)]).start() for _ in range(multiprocessing.cpu_count())]"
    Here is what I used in the container to make it wait on port 5000:
        nc -lu -p 5000 -v
