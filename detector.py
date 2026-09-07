```python
import time
from collections import defaultdict


class DeauthDetector:

    def __init__(self, window=10, threshold=5):
        self.window = window
        self.threshold = threshold

        self.events = defaultdict(list)
        self.alerts = []

    def analyze(self, packet_info):

        if not packet_info:
            return None

        subtype = packet_info.get("subtype", "")

        # Only analyze relevant management events
        if subtype not in [
            "Deauthentication",
            "Disassociation"
        ]:
            return None

        source = packet_info.get("source", "Unknown")
        destination = packet_info.get("destination", "Unknown")

        key = (source, destination)

        now = time.time()

        self.events[key].append(now)

        # Keep only recent events
        self.events[key] = [
            timestamp
            for timestamp in self.events[key]
            if now - timestamp <= self.window
        ]

        count = len(self.events[key])

        if count < self.threshold:
            return None

        risk_score = self.calculate_risk(count)

        if risk_score >= 80:
            severity = "HIGH"

        elif risk_score >= 50:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        alert = {
            "timestamp": packet_info.get("timestamp"),
            "source": source,
            "destination": destination,
            "event": subtype,
            "count": count,
            "risk_score": risk_score,
            "severity": severity
        }

        self.alerts.append(alert)

        # Keep dashboard manageable
        self.alerts = self.alerts[-100:]

        return alert

    def calculate_risk(self, count):

        if count >= 30:
            return 100

        if count >= 20:
            return 90

        if count >= 10:
            return 80

        if count >= 5:
            return 60

        return 20

    def get_alerts(self):
        return self.alerts

    def clear(self):
        self.events.clear()
        self.alerts.clear()
```
