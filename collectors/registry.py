import winreg, datetime, ctypes
from threading import Thread, Event

TARGET_HIVES = {
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_USERS": winreg.HKEY_USERS,
            "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG
        }

def getKeyLastWritten(hive, subkey):
        """Queries the Windows API to get the Last Written filetime of a key."""
        FILETIME = ctypes.c_ulonglong
        last_write_time = FILETIME()
        access_mask = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        try:
            with winreg.OpenKey(hive, subkey, 0, access_mask) as key:
                # Call native Windows API RegQueryInfoKeyW
                result = ctypes.windll.advapi32.RegQueryInfoKeyW(
                    int(key), None, None, None, None, None, None, None, None, None, None, ctypes.byref(last_write_time)
                )
                if result == 0:
                    # Convert Windows FILETIME (100-nanosecond intervals since Jan 1, 1601) to Unix timestamp
                    # 116444736000000000 is the epoch difference
                    unix_ts = (last_write_time.value - 116444736000000000) / 10000000
                    return datetime.datetime.fromtimestamp(unix_ts).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
        return "UNKNOWN"

class RegistryCollector:

    def __init__(self, stop_event):
        self.data = []
        self.stop_event = stop_event
        self.allKeys = {}
        self.target_hives = TARGET_HIVES


    def run(self):
        # self.listRegistryKeys()
        # self.data.append(self.running_processes)
        threads = []

        # Spin up a thread for each hive
        for name, hiveId in self.target_hives.items():
            thread = Thread(
                target=self.scan,
                args=(name, hiveId),
                name=f"scan_{name}"
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    

    def scan(self, hiveName, hiveId):
        try:
            keys = self.listRegistryKeys(hiveId)
            self.allKeys[hiveName] = keys
        except Exception as e:
            # If a major error happens, capture it here instead of crashing the thread loop
            print(f"\n[ERROR] Thread {hiveName} failed safely: {e}")
            self.allKeys[hiveName] = []

        self.allKeys[hiveName] = keys

    def listRegistryKeys(self, hive, subkey="", collectedKeys=None):
        # Check if stop event is set to allow safe mid-scan interruption
        if self.stop_event.is_set():
            return collectedKeys if collectedKeys else []
        
        if collectedKeys is None:
            collectedKeys = [] # Initialize only on first call
        
        try:
            access_mask = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            with winreg.OpenKey(hive, subkey, 0, access_mask) as key:
                valueIndex = 0
                while True:
                    try:
                        name, data, data_type = winreg.EnumValue(key, valueIndex)
                        # fullValuePath = f"{subkey}\\{name}" if subkey else name
                        # print(f"[VALUE] {fullValuePath} -> Type: {data_type}, Data: {data}")
                        # 2. Append the found keys to our list

                        collectedKeys.append((subkey, name, data_type, data)) 
                        valueIndex += 1
                    except OSError:
                        break
                subkeyIndex = 0
                while True:
                    try: 
                        subkeyName = winreg.EnumKey(key, subkeyIndex)
                        fullPath = f"{subkey}\\{subkeyName}" if subkey else subkeyName
                        # print(fullPath)

                        self.listRegistryKeys(hive, fullPath, collectedKeys)
                        subkeyIndex += 1
                    except OSError:
                        break
                    
        except PermissionError:
            pass
        except OSError:
            pass

        return collectedKeys
        


if __name__ == "__main__":
    threads = []

    # Spin up a thread for each hive
    for name, hiveId in target_hives.items():
        thread = Thread(
            target=scan,
            args=(name, hiveId)
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("\nAll threads finished!")
    print(f"Total HKCR items: {len(allKeys.get('HKEY_CLASSES_ROOT', []))}")
    print(f"Total HKCU items: {len(allKeys.get('HKEY_CURRENT_USER', []))}")
    print(f"Total HKLM items: {len(allKeys.get('HKEY_LOCAL_MACHINE', []))}")
    print(f"Total HKU items: {len(allKeys.get('HKEY_USERS', []))}")
    print(f"Total HKCC items: {len(allKeys.get('HKEY_CURRENT_CONFIG', []))}")