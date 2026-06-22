import sqlite3, pyshark
import datetime
from collectors import registry


DB_NAME = "alert.db"

def sanitize_string(val):
    if not isinstance(val, str):
        return val
    try:
        val.encode('utf-8')
        return val
    except UnicodeEncodeError:
        cleanBytes = val.encode('utf-8', errors='surrogatepass')
        return cleanBytes.decode('utf-8', errors='ignore')

def save_registry(registry_data):        
    conn = get_connection()
    cursor = conn.cursor()

    parsedRows = []
    scannedAtTimestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    hiveNameToId = registry.TARGET_HIVES
    for hive_name, items in registry_data.items():
        rawHiveId = hiveNameToId.get(hive_name)

        for subkey_path, value_name, data_type_id, raw_value in items:
        
            data_type_map = {
                1: "REG_SZ",
                2: "REG_EXPAND_SZ",
                3: "REG_BINARY",
                4: "REG_DWORD",
                7: "REG_MULTI_SZ",
                11: "REG_QWORD"
            }
            data_type_string = data_type_map.get(data_type_id, f"UNKNOWN_{data_type_id}")

            # 3. Clean and sanitize the 'value_data' payload column
            # Binary data (REG_BINARY) will crash DB strings; convert it to hex instead
            if isinstance(raw_value, bytes):
                processed_data = raw_value.hex()
            elif isinstance(raw_value, list):
                # REG_MULTI_SZ returns a list of strings; join them cleanly
                processed_data = " | ".join(raw_value)
            else:
                # Numbers and standard strings map cleanly to text fields
                processed_data = str(raw_value)

            # --- NEW: Fetch the Windows Key Last Written Time ---
            last_written_time = "UNKNOWN"
            if rawHiveId:
                last_written_time = registry.getKeyLastWritten(rawHiveId, subkey_path)

            # 4. Construct a row matching your database columns exactly
            db_row = {
                "hive": hive_name,
                "key_path": subkey_path if subkey_path else "\\", # Handle root keys safely
                "value_name": value_name if value_name else "(Default)",
                "data_type": data_type_string,
                "value_data": processed_data,
                'last_written': last_written_time,
                "scanned_at": scannedAtTimestamp
            }
            parsedRows.append(db_row)

    cleanedTupleData = []
    tupleData = [
        (r['hive'], r['key_path'], r['value_name'], r['data_type'], r['value_data'], r['last_written'], r['scanned_at'])
        for r in parsedRows
    ]
    for row in tupleData:
        cleanedRow = tuple(sanitize_string(item) for item in row)
        cleanedTupleData.append(cleanedRow)
    insertQuery = """
        INSERT INTO registry (
            hive, 
            key_path, 
            value_name, 
            data_type, 
            value_data, 
            last_written, 
            scanned_at 
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """


    cursor.executemany(insertQuery, cleanedTupleData)
    conn.commit()
    conn.close()

def save_session(packet_data, process_data):
    # Upload packet traffic to db
    
    conn = get_connection()
    cursor = conn.cursor()
    print(f"Packets: {len(packet_data)}")
    for packet in packet_data:
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
    conn.commit()

    # Upload process data to DB
    for snapshot in process_data:
        for proc in snapshot:
            pid = proc.get('pid')
            name = proc.get('name')
            status = proc.get('status')
            username = proc.get('username')
            cpu = proc.get('cpu_percent')
            mem = proc.get('memory_info')
            time = proc.get('create_time')
            exe = proc.get('exe')

            cmdline_list = proc.get('cmdline')
            cmd = " ".join(cmdline_list) if cmdline_list else ""

            cursor.execute("""
                INSERT INTO processes
                (
                    pid,
                    name,
                    status,
                    cpu_percentage,
                    memory_percentage,
                    create_time,
                    exe,
                    cmdline
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pid,
                name,
                status,
                cpu,
                mem,
                time,
                exe,
                cmd
            ))
    conn.commit()
    conn.close()


def get_connection():
    return sqlite3.connect(DB_NAME)
'''
        'pid',
        'name',
        'status',
        'username',
        'cpu_percent',
        'memory_percent',
        'create_time',
        'exe',
        'cmdline'
'''
def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()
    # Events table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hive TEXT,
            key_path TEXT,
            value_name TEXT,
            data_type TEXT,
            value_data TEXT,
            last_written TEXT,
            scanned_at TEXT
        )""")
    # Alerts Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER,
            name TEXT,
            status TEXT,
            cpu_percentage INTEGER,
            memory_percentage INTEGER,
            create_time TEXT NOT NULL,
            exe TEXT,
            cmdline TEXT
        )""")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS net (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            protocol TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            packet_size INTEGER,
            raw_packet BLOB
        )""")

def log_event(
        event_record_id,
        event_id,
        timestamp,
        hostname,
        xml
):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO events
        (
            event_record_id,
            event_id,
            timestamp,
            hostname,
            raw_XML
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        event_record_id,
        event_id,
        timestamp,
        hostname,
        xml
    ))

    conn.commit()
    conn.close()