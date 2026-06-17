import psutil
import time
import datetime
import json
from database import initialize_database, log_process_event

# Living of the Land Binaries
with open("lolbins.json", "r") as f:
    LOLBINS = json.load(f)

def getProc():
    processes = {}
    for proc in psutil.process_iter(['pid', 'name', 'username', 'ppid', 'cmdline', 'create_time']):
        p_info = proc.info
        processes[p_info['pid']] = {
            'pid': p_info['pid'],
            'name': p_info['name'],
            'username': p_info['username'],
            'ppid': p_info['ppid'],
            'cmdline': p_info['cmdline'],
            'create_time': p_info['create_time']
        }
    return processes
# will pass diff_processes to this function and check if any of the new processes are in the lolbins list, if so, generate an alert
def generateAlert(process):

    lolbin = LOLBINS.get(process['name'].lower())
    if not lolbin:
        return

    commandLine = " ".join(process['cmdline']) if process['cmdline'] else ""

    rawTime = process['create_time']
    readableTime = datetime.datetime.fromtimestamp(rawTime).strftime("%H:%M:%S %Y-%m-%d")

    severity = lolbin["severity"]
    print(
        f"[{severity.upper()}]"
        f"{process['name']} was started by"
        f"{process['username']} at {readableTime}"
    )

    log_process_event(
        timestamp=readableTime,
        pid=process['pid'],
        ppid=process['ppid'],
        process_name=process['name'],
        command_line=commandLine,
        username=process['username']
        )


def main():
    initialize_database()
    base_processes = getProc()
    while True:
        # Sleep for a while before checking for new processes
        time.sleep(3) 
        new_processes = getProc()
        
        # Compare the new processes with the base processes to find any new ones
        diff_processes = new_processes.keys() - base_processes.keys()
        if diff_processes:
            for pid in diff_processes:
                # Scan new process
                generateAlert(new_processes[pid])
            
            
            #print(f"New processes: {diff_processes}")
            #for pid in diff_processes:
                #print(f"PID: {pid}, Name: {new_processes[pid]['name']}, User: {new_processes[pid]['username']}, cmdline: {new_processes[pid]['cmdline']}, create_time: {new_processes[pid]['create_time']}")

        base_processes = new_processes  # Update the base processes for the next iteration

if __name__ == "__main__":
    main()
