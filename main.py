#!/usr/bin/env python3

from os import walk
from os.path import join, abspath
from hashlib import sha256
from datetime import datetime, timedelta
from pathlib import Path
from subprocess import run
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import re
import time
import threading
from collections import defaultdict

MONITOR_FOLDER = "/etc"
LOG_FILE = "./hids.log"
FIRST_HASHES_FILE = "first_hashes.csv"
SSH_FILE = "/var/log/auth.log"

# --- SSH Brute Force Detection Settings ---
FAILED_LOGIN_THRESHOLD = 5
DETECTION_WINDOW_SECONDS = 120

# Regex to parse failed SSH login lines from auth.log
# Only looks for 'Failed password' so it works across different OS log formats
FAILED_SSH_PATTERN = re.compile(
    r"Failed password for (?:invalid user\s+)?(\S+)"
    r"\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})"
)

def monitor_ssh_log():
    # failed_attempts[ip] = list of (timestamp, username) tuples
    failed_attempts = defaultdict(list)

    try:
        with open(SSH_FILE, "r") as f:
            f.seek(0, 2)  # jump to end of file (tail mode)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue

                match = FAILED_SSH_PATTERN.search(line)
                if not match:
                    continue

                username, ip = match.group(1), match.group(2)
                event_time = datetime.now()

                failed_attempts[ip].append((event_time, username))

                # Remove entries outside the rolling window
                cutoff = datetime.now() - timedelta(seconds=DETECTION_WINDOW_SECONDS)
                failed_attempts[ip] = [
                    (t, u) for t, u in failed_attempts[ip] if t >= cutoff
                ]

                count = len(failed_attempts[ip])

                print("[{}] SSH failed login: user='{}' ip='{}' (failures in window: {})".format(event_time.strftime("%d/%m/%Y %l:%M:%S %p"), username, ip, count))
                alert("Failed SSH login from ip {}".format(ip))
                log(event_time.strftime("%d/%m/%Y %l:%M:%S %p"), "ssh", "medium", ip, "Failed SSH login from {} to user {}".format(ip, username))

                if count == FAILED_LOGIN_THRESHOLD:
                    usernames_seen = ", ".join(sorted({u for _, u in failed_attempts[ip]}))
                    event_time2 = datetime.now().strftime("%d/%m/%Y %l:%M:%S %p")
                    print("[{}] *** BRUTE FORCE SSH LOGIN DETECTED *** from ip '{}' | {} failed logins in {}s | usernames tried: {}".format(event_time2, ip, count, DETECTION_WINDOW_SECONDS, usernames_seen))
                    alert("BRUTE FORCE SSH LOGIN DETECTED")
                    log(event_time2, "ssh", "high", ip, "5 Failed logins from ip {}".format(ip))

    except FileNotFoundError:
        print(f"[WARNING] SSH log not found: {SSH_FILE}. SSH monitoring disabled.")
    except PermissionError:
        print(f"[WARNING] No permission to read {SSH_FILE}. Try running as root.")

# child class of the file system monitor
class FileMonitor(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            time = datetime.now().strftime("%d/%m/%Y %l:%M:%S %p")
            print("[{}] File created:       {}".format(time, event.src_path))
            alert("File created {}".format(event.src_path))
            log(time, "file", "low", event.src_path, "File created: {}".format(event.src_path))
    def on_deleted(self, event):
        if not event.is_directory:
            time = datetime.now().strftime("%d/%m/%Y %l:%M:%S %p")
            print("[{}] File deleted:       {}".format(time, event.src_path))
            alert("File deleted {}".format(event.src_path))
            log(time, "file", "low", event.src_path, "File deleted: {}".format(event.src_path))
    def on_modified(self, event):
        if not event.is_directory:
            time = datetime.now().strftime("%d/%m/%Y %l:%M:%S %p")
            print("[{}] File modified:      {}".format(time, event.src_path))
            alert("File modified {}".format(event.src_path))
            log(time, "file", "low", event.src_path, "File modified: {}".format(event.src_path))
        
# gets the hash of a file
def calculate_hash(filepath):
    sha = sha256()
    try:
        with open(filepath, "rb") as file:
            data = file.read()
            sha.update(data) # hash data from file
    except (PermissionError, OSError, FileNotFoundError) as exc:
        return f"ERROR: {exc}"
    return sha.hexdigest()

# creates hashes for all files and stores them in memory and saves them to a csv file  
def calculate_first_hashes():
    csv = "File,SHA256 Hash"
    
    # recursively looks through folder
    for root, _, files in walk(MONITOR_FOLDER):
        for file_name in files:
            file_path = "{}/{}".format(root, file_name) # path to file
            file_hash = calculate_hash(file_path) # hash of file
            print(file_path)
            
            csv += "{},{}\n".format(file_path, file_hash)
    
    try:
        with open(FIRST_HASHES_FILE, "w") as file:
            file.write(csv)
    except Exception:
        print("Failed to log initial file hashes")

# notifies the user
def alert(message):
    try:
        run(["notify-send", "-a", "HIDS", "-u", "critical", message])
    except Exception:
        print("Failed to send desktop notification")

def log(event_time, event_type, severity, source, description): 
    # write to log file
    try:
        with open(LOG_FILE, "a") as log:
            log.write("[Time: {}] [Type: {: <5}] [Severity: {: <8}] [Source: {}] [Description: {}]\n".format(event_time, event_type, severity, source, description))
    except (PermissionError, OSError):
        print("Failed to write to log")
        
def main():
    # hash files first
    print("Hashing all files")
    first_hashes = calculate_first_hashes()
    
    # Start SSH brute force monitor in a background thread
    ssh_thread = threading.Thread(target=monitor_ssh_log, daemon=True)
    ssh_thread.start()
    print(f"Monitoring SSH log: {SSH_FILE}")

    # setup code to watch director
    monitor = Observer()
    event_handler = FileMonitor()
     
    monitor.schedule(event_handler, Path(MONITOR_FOLDER).absolute(), recursive=True)
    monitor.start()
    print("Monitoring", Path(MONITOR_FOLDER).absolute())
    
    try:
        while monitor.is_alive():
            monitor.join(1)
    finally:
        monitor.stop()
        monitor.join()


main()




