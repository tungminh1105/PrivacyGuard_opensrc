import time
import etw

PROVIDERS = [
    etw.ProviderInfo("Microsoft-Windows-Kernel-Process",
                     etw.GUID("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")),
    etw.ProviderInfo("Microsoft-Windows-Kernel-File",
                     etw.GUID("{EDD08927-9CC4-4E65-B970-C2560FB5C289}")),
    etw.ProviderInfo("Microsoft-Windows-Kernel-Network",
                     etw.GUID("{7DD42A49-5329-4832-8DFD-43D979153A88}")),
]

count = 0

def on_event(event):
    global count
    count += 1
    text = repr(event)
    print(f"[{count}] {text[:400]}")

if __name__ == "__main__":
    job = etw.ETW(providers=PROVIDERS, event_callback=on_event)
    job.start()
    print("60s to download some files")
    try:
        time.sleep(60)
    finally:
        job.stop()
        print(f"SUM: {count}")