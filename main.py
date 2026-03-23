#!/usr/bin/python3

from os import walk
from os.path import join
from hashlib import sha256
from datetime import datetime
from pathlib import Path
from subprocess import run
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

MONITOR_FOLDER = "/etc"
LOG_FILE = "/usr/hids.log"
FIRST_HASHES_FILE = "/usr/first_hashes.csv"

def main():
    # hash files first
    print("Hashing all files")
    first_hashes = calculate_first_hashes()
    
    # setup code to watch director
    monitor = Observer()
    event_handler = FileMonitor(first_hashes)
     

    monitor.schedule(event_handler, Path(MONITOR_FOLDER).absolute(), recursive=True)
    monitor.start()
    print("Monitoring", Path(MONITOR_FOLDER).absolute())
    
    try:
        while monitor.is_alive():
            monitor.join(1)
    finally:
        monitor.stop()
        monitor.join()

# child class of the file system monitor
class FileMonitor(FileSystemEventHandler):
    def __init__(self, first_hashes):
        super().__init__()
        self.first_hashes = first_hashes

    def on_created(self, event):
        if not event.is_directory:
            alert("[{}] File created:       {}".format(datetime.now().strftime("%d/%m/%Y %l:%M:%S %p"), event.src_path))
        else:
            alert("[{}] Directory created:  {}".format(datetime.now().strftime("%d/%m/%Y %l:%M:%S %p"), event.src_path))
            
    def on_moved(self, event):
        if not event.is_directory:
            alert("[{}] File moved:         {}".format(datetime.now().strftime("%d/%m/%Y %l:%M:%S %p"), event.src_path))
        else:
            alert("[{}] Directory moved:    {}".format(datetime.now().strftime("%d/%m/%Y %l:%M:%S %p"), event.src_path))
    
    def on_deleted(self, event):
        if not event.is_directory:
            alert("[{}] File deleted:       {}".format(datetime.now().strftime("%d/%m/%Y %l:%M:%S %p"), event.src_path))
        else:
            alert("[{}] Directory deleted:  {}".format(datetime.now().strftime("%d/%m/%Y %l:%M:%S %p"), event.src_path))

    def on_modified(self, event):
        if event.is_directory:
            return
    
        # check hashes work in progress
        file_path = Path(event.src_path).absolute()
        current_hash = calculate_hash(file_path)
        
        #if current_hash != self.first_hashes.get(file_path):
        alert("[{}] Directory modified: {}".format(datetime.now().strftime("%d/%m/%Y %l:%M:%S %p"), event.src_path))

# gets the hash of a file
def calculate_hash(filepath):
    sha = sha256()
    try:
        file = open(filepath, "rb")
        data = file.read()
        sha.update(data) # hash data from fiel
    except (PermissionError, OSError, FileNotFoundError) as exc:
        return f"ERROR: {exc}"
    return sha.hexdigest()

# creates hashes for all files and stores them in memory and saves them to a csv file   
def calculate_first_hashes():
    csv = "File,SHA256 Hash"
    table = dict()
    x = True
    
    # recursively looks through folder
    for root, _, files in walk(MONITOR_FOLDER):
        for file_name in files:
            file_path = Path(root).joinpath(file_name) # path to file
            file_hash = calculate_hash(file_path) # hash of file
            print(file_path)
            
            csv += f"{file_path},{file_hash}\n"
            table[Path(file_path).absolute()] = file_hash
    
    csv_file = open(FIRST_HASHES_FILE, "w")
    csv_file.write(csv)
    
    return table

# notifies the user
def alert(message):
    print(message)
    
    # second: send desktop notification
    try:
        run(["notify-send", "-u", "critical", "-c" "network.disconnected", message])
    except (subprocess.SubprocessError):
    
        print("can't notify")

main()



