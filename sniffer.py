from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


def packet_callback(packet):
  """This function is called for every packet captured."""
  if packet.haslayer(IP):
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto = ip_layer.proto

    # Map protocol numbers to readable names
    proto_name = "OTHER"
    if proto == 6:
      proto_name = "TCP"
    elif proto == 17:
      proto_name = "UDP"
    elif proto == 1:
      proto_name = "ICMP"

    print(f"[+] Packet: {src_ip} ---> {dst_ip} | Protocol: {proto_name}")

    # Extract payload if available
    try:
      if packet.haslayer(TCP) or packet.haslayer(UDP):
        payload = bytes(packet.payload)
        if payload:
          # Print a snippet of the payload (first 50 bytes)
          print(f"    Payload Preview: {payload[:50]}")
    except Exception as e:
      print(f"    Could not extract payload: {e}")

    print("-" * 50)


def main():
  print("=" * 50)
  print("Starting Network Sniffer...")
  print("Capturing traffic. Press Ctrl+C to stop.")
  print("=" * 50)

  # Start sniffing
  # prn: callback function for each packet
  # count: number of packets to capture (0 means infinite)
  # store: False to save memory during long captures
  sniff(prn=packet_callback, count=15, store=False)


if __name__ == "__main__":
  main()
