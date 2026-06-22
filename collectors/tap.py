import pyshark, sqlite3, msvcrt
import time

class PacketCollector:
    def __init__(self, stop_event):
        self.stop_event = stop_event
        self.data = []
        self.capture = pyshark.LiveCapture(interface='Ethernet 3')

    def run(self):
        for packet in self.capture.sniff_continuously():
            self.data.append(packet)
            if self.stop_event.is_set():
                break
'''
        while not self.stop_event.is_set():
            packet = self.capture.sniff_continuously()
            self.data.append(packet)
            time.sleep(1)
            '''

def record():
    recording = 1
    data = []
    x = 0
    capture = pyshark.LiveCapture(interface='Ethernet 3')

    while True:
        packet = capture.sniff_continuously()
        data.append(packet)

        if msvcrt.kbhit():
            break
        return data
    
    if recording == 1:
        for packet in capture.sniff_continuously():
            # print(packet)
            data.append(packet)
            x += 1
            print(x)
            if x == 30:
                recording = 0
                break
        toDB(data)




def toDB(data):
    for packet in data:
        protocol = packet.highest_layer
        timestamp = str(packet.sniff_time)
        packet_size = int(packet.length)
        rawData = str(packet)

        # Extract IPs
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
        else:
            src_ip = 'N/A'
            dst_ip = 'N/A'


        # Extract ports
        if 'TCP' in packet:
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
        elif 'UDP' in packet:
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport
        else:
            src_port = "N/A"
            dst_port = "N/A"

        with sqlite3.connect(database='alert.db') as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO net
                (
                    timestamp,
                    protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    packet_size,
                    raw_packet
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                packet_size,
                rawData
            ))
    conn.commit
    conn.close
     

if __name__ == '__main__':
    record()
