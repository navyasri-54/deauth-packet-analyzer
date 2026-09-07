```python
from datetime import datetime


class PacketAnalyzer:
    """
    Extracts useful information from 802.11 packets.
    """

    def __init__(self):
        self.packets = []

    def analyze_packet(self, packet):
        """
        Analyze a Scapy packet.

        Returns a dictionary containing useful packet information.
        """

        try:
            from scapy.layers.dot11 import Dot11

            if not packet.haslayer(Dot11):
                return None

            dot11 = packet[Dot11]

            packet_type = {
                0: "Management",
                1: "Control",
                2: "Data",
                3: "Extension"
            }.get(dot11.type, "Unknown")

            subtype_names = {
                0: "Association Request",
                1: "Association Response",
                4: "Probe Request",
                5: "Probe Response",
                8: "Beacon",
                10: "Disassociation",
                11: "Authentication",
                12: "Deauthentication",
                13: "Action"
            }

            subtype = subtype_names.get(
                dot11.subtype,
                f"Subtype {dot11.subtype}"
            )

            info = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "source": dot11.addr2 or "Unknown",
                "destination": dot11.addr1 or "Unknown",
                "bssid": dot11.addr3 or "Unknown",
                "type": packet_type,
                "subtype": subtype
            }

            self.packets.append(info)

            return info

        except Exception as error:
            return {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "source": "Unknown",
                "destination": "Unknown",
                "bssid": "Unknown",
                "type": "Unknown",
                "subtype": "Error",
                "error": str(error)
            }

    def get_packets(self):
        return self.packets

    def clear(self):
        self.packets.clear()
```
