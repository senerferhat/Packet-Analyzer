import tkinter as tk
import tkinter.filedialog
from tkinter import scrolledtext
from threading import Thread
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP
from collections import Counter

ip_counter = Counter()
THRESHOLD =50  # adjust this value
stop_sniffing = False

def packet_handler(packet):
    global stop_sniffing
    if stop_sniffing:
        return True # Returning True in the sniff's prn function stops the sniff

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        ip_counter[ip_src] += 1
        result = f'IP Packet: Source IP: {ip_src} ---- Destination IP: {ip_dst}\n'
        txt.insert(tk.END, result)

    if packet.haslayer(TCP):
        txt.insert(tk.END, "TCP Packet detected.\n")

    if packet.haslayer(UDP):
        txt.insert(tk.END, "UDP Packet detected.\n")
        
    if packet.haslayer(ICMP):
        txt.insert(tk.END, "ICMP Packet detected.\n")
    
    txt.see(tk.END)

def capture_live():
    global stop_sniffing
    stop_sniffing = False
    sniff(prn=packet_handler, stop_filter=lambda p: stop_sniffing)

def stop_capture():
    global stop_sniffing
    stop_sniffing = True

def read_pcap(file_path):
    packets = rdpcap(file_path)
    for packet in packets:
        packet_handler(packet)

def print_stats():
    txt.insert(tk.END, "Most common source IPs:\n")
    for ip, count in ip_counter.most_common(5):
        txt.insert(tk.END, f"{ip}: {count} packets\n")
    txt.see(tk.END)  # Add this line after inserting the text

def check_anomalies():
    txt_anomalies.insert(tk.END, "Checking for anomalies...\n")
    for ip, count in ip_counter.items():
        if count > THRESHOLD:
            txt_anomalies.insert(tk.END, f"Potential anomaly: {ip} has sent {count} packets\n")
    txt_anomalies.see(tk.END)  # Add this line after inserting the text

def start_live_capture():
    t = Thread(target=capture_live)
    t.start()

def stop_live_capture():
    t = Thread(target=stop_capture)
    t.start()

def start_pcap_reading():
    # replace 'path_to_your_file.pcap' with your file path
    t = Thread(target=read_pcap, args=('path_to_your_file.pcap',))
    t.start()

def load_pcap():
    filepath = tkinter.filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap")])
    if filepath:
        packets = rdpcap(filepath)
        for packet in packets:
            packet_handler(packet)

def start_printing_stats():
    print_stats()  # Don't run in a separate thread

def start_checking_anomalies():
    check_anomalies()  # Don't run in a separate thread

class ToggleButton(tk.Button):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, command=self._on_toggle, **kwargs)
        self._is_toggled = False

    def _on_toggle(self):
        self._is_toggled = not self._is_toggled
        if self._is_toggled:
            self.config(text="Stop Live Capture")
            Thread(target=capture_live).start()
        else:
            self.config(text="Start Live Capture")
            Thread(target=stop_capture).start()

root = tk.Tk()
root.title("Packet Analyzer")
root.resizable(True, True)

# Configure the grid
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=1)
root.grid_rowconfigure(2, weight=1)
root.grid_rowconfigure(3, weight=1)
root.grid_rowconfigure(4, weight=1)

btn1 = ToggleButton(root, text="Start Live Capture", height=2, width=20)
btn1.grid(column=1, row=0, padx=10, pady=10, sticky='nsew')

btn2 = tk.Button(root, text="Print Statistics", command=start_printing_stats, height=2, width=20)
btn2.grid(column=1, row=1, padx=10, pady=10, sticky='nsew')

btn3 = tk.Button(root, text="Check Anomalies", command=start_checking_anomalies, height=2, width=20)
btn3.grid(column=1, row=2, padx=10, pady=10, sticky='nsew')

btn4 = tk.Button(root, text="Load PCAP", command=load_pcap, height=2, width=20)
btn4.grid(column=1, row=3, padx=10, pady=10, sticky='nsew')

txt = scrolledtext.ScrolledText(root, width=70, height=10)
txt.grid(column=0, row=0, rowspan=4, padx=10, pady=10, sticky='nsew')

txt_anomalies = scrolledtext.ScrolledText(root, width=70, height=10)
txt_anomalies.grid(column=0, row=4, padx=10, pady=10, sticky='nsew')

root.mainloop()

