import win32evtlog, win32evtlogutil, win32con, pythoncom
import sys
import xml.etree.ElementTree as ET
from database import initialize_database, log_event

# Define sysmon events and fetch all events
CHANNEL = 'Microsoft-Windows-Sysmon/Operational'
QUERY = '*'

#Callback function to handle events in real time
def callback(action, context, event_handle):
    if action == win32evtlog.EvtSubscribeActionDeliver:
        try:
            # Render the event to XML format for easy parsing
            xml_str = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            print(f"[+] New Sysmon Event Received:")
            print(xml_str)
            print("-" * 40)
            toDB(xml_str)
        except Exception as e:
            print(f"Error rendering event: {e}")
    return 0

def toDB(data):
    root = ET.fromstring(data)

    ns = {
        "e": "http://schemas.microsoft.com/win/2004/08/events/event"
    }
    event = {
        "event_id": int(root.find(".//e:EventID", ns).text),
        "event_record_id": int(root.find(".//e:EventRecordID", ns).text),
        "hostname": root.find(".//e:Computer", ns).text,
        "timestamp": root.find(".//e:TimeCreated", ns).attrib["SystemTime"],
        "event_data": {}
    }

    for field in root.findall(".//e:EventData/e:Data", ns):

        name = field.attrib["Name"]

        event["event_data"][name] = (
            field.text if field.text else ""
        )
    print("TESTING HERE LOOK AT ME")
    # print(type(event))
    # print(event)

    log_event(
        event_record_id=event["event_record_id"],
        event_id=event["event_id"],
        timestamp=event["timestamp"],
        hostname=event["hostname"],
        xml=data
        )
    return event


def main():
    print(f"Listening to {CHANNEL} for live events. Press Ctrl+C to exit.")
    
    # Create the push subscription
    subscription = win32evtlog.EvtSubscribe(
        ChannelPath=CHANNEL,
        Flags=win32evtlog.EvtSubscribeToFutureEvents,  # Listen only for new events
        Query=QUERY,
        Callback=callback,                       # Our callback function
    )
    
    # Pump Windows messages to keep the callback alive and listening
    try:
        while True:
            pythoncom.PumpWaitingMessages()
    except KeyboardInterrupt:
        print("Stopping listener...")
        sys.exit(0)


if __name__ == '__main__':
    main()