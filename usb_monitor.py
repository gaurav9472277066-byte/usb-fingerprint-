import wmi
import time
import json
from datetime import datetime
from .device_fingerprint import create_fingerprint

KNOWN_DEVICES_PATH = "data/known_devices.json"
LOG_FILE = "logs/usb_activity.log"


def log_event(message):
    with open(LOG_FILE, "a") as log:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"[{timestamp}] {message}\n")
    print(message)


def load_known_devices():
    try:
        with open(KNOWN_DEVICES_PATH, "r") as file:
            return json.load(file)
    except:
        return []


def save_known_device(fingerprint):
    devices = load_known_devices()
    devices.append(fingerprint)
    with open(KNOWN_DEVICES_PATH, "w") as file:
        json.dump(devices, file, indent=4)


def is_known_device(fingerprint):
    devices = load_known_devices()
    return any(
        d["vendor_id"] == fingerprint["vendor_id"]
        and d["product_id"] == fingerprint["product_id"]
        and d["serial"] == fingerprint["serial"]
        for d in devices
    )


def detect_suspicious_behavior(fp):
    alerts = []

    if fp["serial"] is None:
        alerts.append("Warning: Missing serial number — could be spoofed.")

    if fp["vendor"] is None:
        alerts.append("Warning: Unknown vendor — potentially unsafe device.")

    return alerts


def monitor_usb_events():
    watcher = wmi.WMI()

    log_event("USB Monitoring Started...\n")

    while True:
        for usb in watcher.Win32_USBControllerDevice():
            device = usb.Dependent

            fingerprint = create_fingerprint({
                "VendorID": device.PNPDeviceID[8:12] if device.PNPDeviceID else None,
                "ProductID": device.PNPDeviceID[13:17] if device.PNPDeviceID else None,
                "SerialNumber": device.SerialNumber,
                "Manufacturer": device.Manufacturer,
                "Product": device.Name
            })

            log_event(f"USB Connected: {fingerprint}")

            if is_known_device(fingerprint):
                log_event("Known device connected.")
            else:
                log_event("Unknown device detected.")

                alerts = detect_suspicious_behavior(fingerprint)
                for alert in alerts:
                    log_event(f"ALERT: {alert}")

                save_known_device(fingerprint)

        time.sleep(3)
