import tkinter as tk
from scapy.all import sniff
from threading import Thread
import datetime

class PacketSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Packet Sniffer")
        
        self.text_area = tk.Text(root, height=15, width=100)
        self.text_area.pack()

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack()

    def packet_handler(self, packet):
        # Get the current time for logging
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        packet_info = f"{timestamp} - {packet.summary()}\n"

        # Log the packet information to SniffLog.txt
        with open("SniffLog.txt", "a") as log_file:
            log_file.write(packet_info)

        # Display the packet info in the text area
        self.text_area.insert(tk.END, packet_info)
        self.text_area.see(tk.END)  # Auto-scroll to the end

    def start_sniffing(self):
        Thread(target=self.sniff_packets).start()

    def sniff_packets(self):
        sniff(prn=self.packet_handler)  # Sniff packets indefinitely

# Create the main window
root = tk.Tk()
sniffer = PacketSniffer(root)
root.mainloop()
