# logger.py

from threading import Lock
from queue import Queue

scan_logs = []
log_lock = Lock()
log_stream_queue = Queue()  # ✅ For SSE streaming

def log_message(msg: str):
    print(msg)
    formatted = f"[{msg}]"
    with log_lock:
        scan_logs.append(formatted)
        if len(scan_logs) > 100:
            scan_logs.pop(0)
    log_stream_queue.put(formatted)

def get_logs():
    with log_lock:
        return list(scan_logs)

def clear_logs():
    with log_lock:
        scan_logs.clear()
    with log_stream_queue.mutex:
        log_stream_queue.queue.clear()

def stream_log_generator():
    yield "retry: 2000\n\n"  # SSE reconnect delay
    while True:
        msg = log_stream_queue.get()
        yield f"data: {msg}\n\n"
