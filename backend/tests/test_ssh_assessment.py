import os
import unittest

from graph import build_investigation_graph


SSH_LOG_SAMPLE = """2026-11-21 09:14:02 SERVER01 sshd[1021]: Failed password for root from 185.220.101.45 port 51234 ssh2

2026-11-21 09:14:08 SERVER01 sshd[1022]: Failed password for root from 185.220.101.45 port 51235 ssh2

2026-11-21 09:14:15 SERVER01 sshd[1023]: Failed password for admin from 185.220.101.45 port 51236 ssh2

2026-11-21 09:14:22 SERVER01 sshd[1024]: Failed password for admin from 185.220.101.45 port 51237 ssh2

2026-11-21 09:14:31 SERVER01 sshd[1025]: Failed password for root from 185.220.101.45 port 51238 ssh2

2026-11-21 09:15:03 SERVER01 sshd[1026]: Accepted password for admin from 185.220.101.45 port 51239 ssh2

2026-11-21 09:15:10 SERVER01 sshd[1027]: pam_unix(sshd:session): session opened for user admin"""


class SSHAssessmentRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.pop("ABUSEIPDB_API_KEY", None)
        os.environ.pop("VT_API_KEY", None)

    def test_failed_then_successful_ssh_sequence_is_high_severity_hypothesis(self):
        graph = build_investigation_graph()
        result = graph.invoke({
            "investigation_id": "ssh-regression",
            "prompt": SSH_LOG_SAMPLE,
            "evidence": [],
            "agent_executions": [],
            "triage": {},
            "threat_intelligence": {},
            "log_analysis": {},
            "correlation": {},
            "risk_report": {},
            "report_status": "in_progress",
        })

        log_analysis = result["log_analysis"]
        self.assertEqual(log_analysis["failed_attempt_count"], 5)
        self.assertEqual(log_analysis["successful_login_count"], 1)
        self.assertEqual(log_analysis["session_event_count"], 1)
        self.assertEqual(log_analysis["source_ips"], ["185.220.101.45"])
        self.assertEqual(log_analysis["target_hosts"], ["SERVER01"])
        self.assertEqual(sorted(log_analysis["affected_usernames"]), ["admin", "root"])
        self.assertEqual(len(log_analysis["events"]), 7)

        correlation = result["correlation"]
        hypothesis = correlation["hypotheses"][0]
        self.assertEqual(
            hypothesis["pattern"],
            "Potential SSH brute-force attack with successful authentication",
        )
        self.assertIn("5 failed SSH authentication", hypothesis["basis"])
        self.assertIn("1 successful login", hypothesis["basis"])
        self.assertIn("not_confirmed", hypothesis)

        report = result["risk_report"]
        self.assertEqual(report["classification"], hypothesis["pattern"])
        self.assertEqual(report["severity"], "high")
        self.assertEqual(report["confidence"], "moderate")
        self.assertIn("Whether the successful login was authorized", report["unknowns"])
        self.assertTrue(
            any("No live threat intelligence findings" in item for item in report["uncertainty"])
        )


if __name__ == "__main__":
    unittest.main()
