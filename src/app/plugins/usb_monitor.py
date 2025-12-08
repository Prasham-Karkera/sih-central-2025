import platform
import threading
import time
import asyncio
from datetime import datetime, timezone

class USBDeviceMonitorPlugin:
    def __init__(self):
        self.name = "USB Device Monitor Plugin"
        self.devices = []
        self.ws_manager = None
        self.monitor_thread = None
        self.stop_thread = False
        self.loop = None

    def _get_connected_usb_devices(self):
        os_name = platform.system().lower()
        devices = []
        try:
            if os_name == "windows":
                try:
                    import wmi
                    c = wmi.WMI()
                    for usb in c.Win32_USBControllerDevice():
                        try:
                            dev = usb.Dependent
                            devices.append(str(dev))
                        except Exception:
                            continue
                except ImportError:
                    return ["wmi module not installed"]
            elif os_name == "linux":
                try:
                    import pyudev
                    context = pyudev.Context()
                    for device in context.list_devices(subsystem='usb', DEVTYPE='usb_device'):
                        model = device.get('ID_MODEL', 'Unknown')
                        vendor = device.get('ID_VENDOR', 'Unknown')
                        node = device.device_node or 'Unknown Node'
                        devices.append(f"{vendor} {model} ({node})")
                except ImportError:
                    # Fallback to lsusb if pyudev is missing
                    import subprocess
                    try:
                        output = subprocess.check_output(["lsusb"]).decode()
                        for line in output.splitlines():
                            parts = line.split(" ", 6)
                            if len(parts) > 6:
                                devices.append(parts[6])
                            else:
                                devices.append(line)
                    except Exception as e:
                        return [f"pyudev missing and lsusb failed: {e}"]

            elif os_name == "darwin":
                import subprocess
                output = subprocess.check_output(["system_profiler", "SPUSBDataType"]).decode()
                for line in output.splitlines():
                    if "Product ID" in line or "Vendor ID" in line or "Manufacturer" in line:
                        devices.append(line.strip())
            else:
                devices.append(f"Unsupported OS: {os_name}")
        except Exception as e:
            devices.append(f"Error: {e}")
        return devices

    def _monitor_usb_devices(self):
        last_devices = set(self._get_connected_usb_devices())
        # Initial population
        self.devices = list(last_devices)
        
        while not self.stop_thread:
            time.sleep(5)
            current_devices = set(self._get_connected_usb_devices())
            added = current_devices - last_devices
            removed = last_devices - current_devices
            
            if added or removed:
                event = {
                    "type": "usb_update",
                    "data": {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "added": list(added),
                        "removed": list(removed),
                        "devices": list(current_devices)
                    }
                }
                self.devices = list(current_devices)
                if self.ws_manager and self.loop:
                    asyncio.run_coroutine_threadsafe(self.ws_manager.broadcast(event), self.loop)
            
            last_devices = current_devices

    def on_load(self, ws_manager, loop):
        print("USB Device Monitor Plugin loaded.")
        self.ws_manager = ws_manager
        self.loop = loop
        self.stop_thread = False
        if not self.monitor_thread or not self.monitor_thread.is_alive():
            self.monitor_thread = threading.Thread(target=self._monitor_usb_devices, daemon=True)
            self.monitor_thread.start()

    def on_unload(self):
        self.stop_thread = True
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
            
    def get_current_devices(self):
        return self._get_connected_usb_devices()
