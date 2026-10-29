
import multiprocessing as mp
import time
import traceback
from collections import Counter

PROVIDER_NAME = "Microsoft-Windows-Kernel-File"
PROVIDER_GUID = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
SESSION_NAME = "AIRD_PayloadInspection"
CAPTURE_SECONDS = 5
MAX_EXAMPLES = 5


def capture_worker(output_queue):
    try:
        from etw import ETW, GUID, ProviderInfo

        counts = Counter()
        examples = []

        def on_event(event_tuple):
            event_id, data = event_tuple
            counts["total"] += 1

            if len(examples) < MAX_EXAMPLES:
                header = data.get("EventHeader", {}) if isinstance(data, dict) else {}
                examples.append({
                    "event_id": event_id,
                    "process_id": header.get("ProcessId"),
                    "thread_id": header.get("ThreadId"),
                    "timestamp": header.get("TimeStamp"),
                    "task_name": data.get("Task Name") if isinstance(data, dict) else None,
                    "description": data.get("Description") if isinstance(data, dict) else None,
                    "keys": list(data.keys())[:25] if isinstance(data, dict) else [],
                    "payload_preview": repr(data)[:900],
                })

        provider = ProviderInfo(
            name=PROVIDER_NAME,
            guid=GUID(PROVIDER_GUID),
            any_keywords=[
                "KERNEL_FILE_KEYWORD_FILEIO",
                "KERNEL_FILE_KEYWORD_CREATE",
                "KERNEL_FILE_KEYWORD_READ",
                "KERNEL_FILE_KEYWORD_WRITE",
                "KERNEL_FILE_KEYWORD_DELETE_PATH",
                "KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH",
            ],
        )

        trace = ETW(
            session_name=SESSION_NAME,
            providers=[provider],
            event_callback=on_event,
        )

        trace.start()
        time.sleep(CAPTURE_SECONDS)

        # Send the captured data before attempting library shutdown.
        output_queue.put({
            "status": "captured",
            "event_count": counts["total"],
            "examples": examples,
        })

        trace.stop()
        output_queue.put({"status": "shutdown_completed"})

    except Exception as exc:
        try:
            output_queue.put({
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc()[-2500:],
            })
        except Exception:
            pass


def main():
    # Windows multiprocessing must use the spawn entry point.
    mp.freeze_support()
    output_queue = mp.Queue()
    worker = mp.Process(target=capture_worker, args=(output_queue,))
    worker.start()

    deadline = time.monotonic() + CAPTURE_SECONDS + 15
    last_status = None

    while time.monotonic() < deadline:
        try:
            result = output_queue.get(timeout=1)
        except Exception:
            if not worker.is_alive():
                break
            continue

        last_status = result.get("status")
        print(f"\nSTATUS: {last_status}")
        print(result)

        if last_status in ("shutdown_completed", "error"):
            break

    if worker.is_alive():
        print("\nWorker did not exit in time; terminating isolated diagnostic process.")
        worker.terminate()
        worker.join(timeout=3)
        print("Worker termination requested.")
    else:
        worker.join(timeout=1)
        print(f"Worker exit code: {worker.exitcode}")

    if last_status is None:
        print("No diagnostic result was received.")


if __name__ == "__main__":
    main()
