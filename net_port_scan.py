import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import threading
import socket
from scapy.all import ARP, Ether, srp
import requests
import csv
import ipaddress
import subprocess

def get_device_manufacturer(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}")
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown Manufacturer"
    except:
        return "Manufacturer Lookup Failed"

def infer_device_type(open_ports):
    if 80 in open_ports or 443 in open_ports:
        return "Web Server/Device"
    elif 22 in open_ports:
        return "SSH Device"
    elif 23 in open_ports:
        return "Telnet Device"
    elif 3389 in open_ports:
        return "Remote Desktop Device"
    elif 445 in open_ports:
        return "File Sharing Device (SMB)"
    else:
        return "Unknown Device"

def is_device_online(ip):
    try:
        result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except:
        return False

def scan_network(network):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    result = srp(packet, timeout=2, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def scan_ports(ip, ports, progress_callback=None):
    open_ports = []
    total = len(ports)
    for i, port in enumerate(ports):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
        if progress_callback:
            progress_callback(i + 1, total)
    return open_ports

def save_results_to_csv(results):
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return
    with open(file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "MAC Address", "Manufacturer", "Device Type", "Open Ports", "Status"])
        for result in results:
            writer.writerow([result['ip'], result['mac'], result['manufacturer'], result['device_type'], result['open_ports'], result['status']])
    output_box.insert(tk.END, f"✅ Results saved to {file_path}\n")

def update_progress(current, total):
    progress_bar["value"] = int((current / total) * 100)
    root.update_idletasks()

def start_scan():
    network = network_entry.get()
    port_start = int(port_start_entry.get())
    port_end = int(port_end_entry.get())
    output_box.delete('1.0', tk.END)
    progress_bar["value"] = 0

    try:
        ipaddress.ip_network(network, strict=False)
    except ValueError:
        output_box.insert(tk.END, "❌ Invalid network range.\n")
        return

    def scan_thread():
        output_box.insert(tk.END, f"🔍 Scanning network: {network}\n\n")
        devices = scan_network(network)
        if not devices:
            output_box.insert(tk.END, "No devices found.\n")
            return

        results = []
        for device in devices:
            ip = device["ip"]
            mac = device["mac"]
            output_box.insert(tk.END, f"📡 Found: {ip} ({mac})\n")

            manufacturer = get_device_manufacturer(mac)
            output_box.insert(tk.END, f"   🏷 Manufacturer: {manufacturer}\n")

            status = "Online" if is_device_online(ip) else "Offline"
            output_box.insert(tk.END, f"   ⚡ Status: {status}\n")

            open_ports = scan_ports(ip, list(range(port_start, port_end + 1)), progress_callback=update_progress)
            device_type = infer_device_type(open_ports)

            results.append({'ip': ip, 'mac': mac, 'manufacturer': manufacturer, 'device_type': device_type, 'open_ports': open_ports, 'status': status})

            if open_ports:
                output_box.insert(tk.END, f"   🔓 Open ports: {open_ports}\n")
                output_box.insert(tk.END, f"   📟 Device Type: {device_type}\n")
            else:
                output_box.insert(tk.END, f"   🔒 No common open ports\n")
            output_box.insert(tk.END, "-" * 40 + "\n")

        output_box.insert(tk.END, "✅ Scan complete.\n")
        export_button.config(command=lambda: save_results_to_csv(results), state=tk.NORMAL)

    threading.Thread(target=scan_thread).start()

root = tk.Tk()
root.title("Advanced Network & Port Scanner")
root.geometry("700x600")

ttk.Label(root, text="Enter Network Range (e.g., 192.168.12.13/24):").pack(pady=5)
network_entry = ttk.Entry(root, width=50)
network_entry.pack(pady=5)
network_entry.insert(0, "192.168.12.13/24")

ttk.Label(root, text="Port Range:").pack(pady=5)
port_frame = ttk.Frame(root)
port_frame.pack(pady=5)
port_start_entry = ttk.Entry(port_frame, width=10)
port_start_entry.insert(0, "1")
port_start_entry.pack(side="left", padx=2)
ttk.Label(port_frame, text="to").pack(side="left")
port_end_entry = ttk.Entry(port_frame, width=10)
port_end_entry.insert(0, "1024")
port_end_entry.pack(side="left", padx=2)

ttk.Button(root, text="Start Scan", command=start_scan).pack(pady=10)

progress_bar = ttk.Progressbar(root, orient="horizontal", length=500, mode="determinate")
progress_bar.pack(pady=5)

output_box = scrolledtext.ScrolledText(root, width=80, height=20)
output_box.pack(pady=10)

export_button = ttk.Button(root, text="Export Results", state=tk.DISABLED)
export_button.pack(pady=10)

root.mainloop()
