import time
from threading import Thread, Event
from collectors.tap import PacketCollector
from collectors.processes import ProcessCollector
from collectors.registry import RegistryCollector
from database import save_session, save_registry
import tkinter as tk

stop_event = None
packet_collector = None
process_collector = None
threads = []
prime = 0

def primeRecord():
    stop_event = Event()
    registry_collector = RegistryCollector(stop_event)
    packet_thread = Thread(
        target=registry_collector.run
    )

    packet_thread.start()
    print("Priming device for recording...")
    time.sleep(5)
    print("Grabbing Registry Keys...")
    #time.sleep(45)
    print("Wrapping things up...")
    packet_thread.join()

    collectedRegistry = registry_collector.allKeys
    save_registry(collectedRegistry)

    print("Ready to record! Click record when you are ready!")



def startRecord():
    global stop_event
    global packet_collector
    global process_collector
    global threads

    print("Starting recording...")
    stop_event = Event()

    packet_collector = PacketCollector(stop_event)
    process_collector = ProcessCollector(stop_event)

    packet_thread = Thread(
        target=packet_collector.run
    )

    process_thread = Thread(
        target=process_collector.run
    )

    threads = [
        packet_thread,
        process_thread
    ]

    for thread in threads:
        thread.start()

def stopRecord():
    global stop_event
    print("Stopping recording")
    stop_event.set()
    for thread in threads:
        thread.join()
    save_session(packet_collector.data,
                 process_collector.data)


root = tk.Tk()
root.geometry("600x400")
root.title("Bastion")

prime_button = tk.Button(root, text="Prime for Recording", command=primeRecord)
prime_button.pack(pady=10)

start_button = tk.Button(root, text="Start Recording", command=startRecord)
start_button.pack(pady=10)

stop_button = tk.Button(root, text="Stop Recording", command=stopRecord)
stop_button.pack(pady=10)




root.mainloop()




