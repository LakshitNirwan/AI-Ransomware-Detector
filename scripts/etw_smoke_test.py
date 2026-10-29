
import time
import traceback
from collections import Counter

from etw import ETW, GUID, ProviderInfo


PROVIDER_NAME = "Microsoft-Windows-Kernel-File"
PROVIDER_GUID = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
SESSION_NAME = "AIRD_KernelFile_SmokeTest"
DURATION_SECONDS = 5
MAX_EXAMPLES = 5

event_counts = Counter()
event_examples = []


def on_event(event_tuple):
    """Count received events and retain only a few examples."""
    try:
        event_id, event_data = event_tuple
        event_counts[PROVIDER_NAME] += 1

        if len(event_examples) < MAX_EXAMPLES:
            event_examples.append({
                "event_id": event_id,
                "data": str(event_data)[:700],
            })
    except Exception:
        print("Callback error:")
        traceback.print_exc()


def main():
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

    started = False

    try:
        print(f"Starting ETW smoke test: {SESSION_NAME}")
        print(f"Provider: {PROVIDER_NAME}")
        print(f"Keyword mask: {provider.any_bitmask:#x}")
        trace.start()
        started = True
        print(f"Capturing for up to {DURATION_SECONDS} seconds...")
        time.sleep(DURATION_SECONDS)

    except Exception as exc:
        print(f"ETW smoke test failed: {type(exc).__name__}: {exc}")
        traceback.print_exc()

    finally:
        if started:
            try:
                trace.stop()
                print("ETW session stopped.")
            except Exception as exc:
                print(f"WARNING: ETW cleanup failed: {exc}")
                traceback.print_exc()

    total = sum(event_counts.values())
    print(f"Events received: {total}")

    for index, example in enumerate(event_examples, start=1):
        print(f"Example {index}: {example}")

    if total:
        print("RESULT: Events received. Inspect examples before mapping fields.")
    else:
        print("RESULT: No events received. This does not prove the provider is unavailable.")


if __name__ == "__main__":
    main()
