
import threading
import time
import traceback
from collections import Counter

from etw import ETW, GUID, ProviderInfo

PROVIDER_NAME = "Microsoft-Windows-Kernel-File"
PROVIDER_GUID = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
SESSION_NAME = "AIRD_KernelFile_Diagnostic"
CAPTURE_SECONDS = 5

event_count = 0


def on_event(event_tuple):
    global event_count
    event_count += 1


def main():
    global event_count

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

    print("Starting ETW diagnostic...")
    print(f"Keyword mask: {provider.any_bitmask:#x}")

    try:
        trace.start()
        print("ETW started successfully.")
        print(f"Capturing for {CAPTURE_SECONDS} seconds...")
        time.sleep(CAPTURE_SECONDS)
        print(f"Capture finished. Events received: {event_count}")

        print("Stopping ETW in a worker thread...")
        stop_thread = threading.Thread(target=trace.stop, daemon=True)
        stop_thread.start()
        stop_thread.join(timeout=8)

        if stop_thread.is_alive():
            print("DIAGNOSTIC: trace.stop() did not finish within 8 seconds.")
            print("Do not start another trace with this session name.")
        else:
            print("ETW shutdown completed.")

    except Exception as exc:
        print(f"Diagnostic failed: {type(exc).__name__}: {exc}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
