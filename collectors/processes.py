import psutil


class ProcessCollector:
    data = []
    def __init__(self, stop_event):
        self.data = []
        self.stop_event = stop_event
        self.running_processes = []

    def run(self):
        while not self.stop_event.is_set():
            self.running_processes = [
                p.info for p in psutil.process_iter(attrs=[
                    'pid',
                    'name',
                    'status',
                    'username',
                    'cpu_percent',
                    'memory_percent',
                    'create_time',
                    'exe',
                    'cmdline'
                ])
            ]
            self.data.append(self.running_processes)


            