import unittest
from src.detector import detect_bruteforce

class DetectorTests(unittest.TestCase):
    def test_detects_five_failures_in_ten_minutes(self):
        events = [{"timestamp": f"2026-11-17T14:0{i}:00Z", "event_type": "login_failed", "src_ip": "192.0.2.10"} for i in range(5)]
        result = detect_bruteforce(events)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["rule_id"], "CSAI-001")

    def test_ignores_success(self):
        self.assertEqual(detect_bruteforce([{"timestamp": "2026-11-17T14:00:00Z", "event_type": "login_success", "src_ip": "192.0.2.10"}]), [])

    def test_ignores_distant_failures(self):
        events = [{"timestamp": f"2026-11-17T{hour:02d}:00:00Z", "event_type": "login_failed", "src_ip": "192.0.2.10"} for hour in range(5)]
        self.assertEqual(detect_bruteforce(events), [])

if __name__ == "__main__":
    unittest.main()
