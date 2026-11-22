import json
import os
import unittest
from unittest.mock import patch

import httpx

from graph import build_investigation_graph


SSH_LOG_SAMPLE = """2026-11-21 09:14:02 SERVER01 sshd[1021]: Failed password for root from 8.8.8.8 port 51234 ssh2
2026-11-21 09:14:08 SERVER01 sshd[1022]: Failed password for root from 8.8.8.8 port 51235 ssh2
2026-11-21 09:14:15 SERVER01 sshd[1023]: Failed password for admin from 8.8.8.8 port 51236 ssh2
2026-11-21 09:14:22 SERVER01 sshd[1024]: Failed password for admin from 8.8.8.8 port 51237 ssh2
2026-11-21 09:14:31 SERVER01 sshd[1025]: Failed password for root from 8.8.8.8 port 51238 ssh2
2026-11-21 09:15:03 SERVER01 sshd[1026]: Accepted password for admin from 8.8.8.8 port 51239 ssh2"""


def groq_reply(content):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": json.dumps(content)}}]}

    return Response()


def response_for_task(task):
    if task.startswith("Classify"):
        return {
            "input_type": "security_log",
            "security_logs_present": True,
            "summary": "The input contains SSH authentication events.",
            "focus_items": ["Review failed and accepted logins"],
        }
    if task.startswith("Interpret the supplied IP"):
        return {
            "interpretation": "The IP is globally routable; no provider findings were supplied.",
            "caveats": ["No reputation claim can be made without provider findings."],
        }
    if task.startswith("Interpret the parsed log"):
        return {
            "interpretation": "Multiple failed logins precede an accepted login.",
            "notable_patterns": ["Failed attempts followed by a successful login"],
            "data_quality_notes": [],
        }
    if task.startswith("Suggest up to three"):
        return {
            "hypotheses": [{
                "pattern": "Potential repeated access attempt",
                "basis": "Five failed SSH attempts and one accepted login were parsed.",
                "confidence": "moderate",
            }],
        }
    return {
        "severity": "medium",
        "severity_rationale": "The supplied evidence warrants review.",
        "executive_summary": "Repeated authentication failures preceded a successful login.",
        "recommendations": [
            "Review the affected account's recent activity",
            "Preserve the original authentication logs",
        ],
        "additional_unknowns": ["Whether the login was authorized"],
    }


class GroqAgentsTest(unittest.TestCase):
    @staticmethod
    def invoke_graph():
        return build_investigation_graph().invoke({
            "investigation_id": "groq-test",
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

    def test_all_agents_use_groq_and_llm_cannot_lower_severity(self):
        requests = []

        def post(url, **kwargs):
            requests.append((url, kwargs))
            task = json.loads(kwargs["json"]["messages"][1]["content"])["task"]
            return groq_reply(response_for_task(task))

        with patch.dict(os.environ, {
            "GROQ_API_KEY": "test-key",
            "GROQ_MODEL": "test-model",
            "ABUSEIPDB_API_KEY": "",
            "VT_API_KEY": "",
        }), \
                patch("llm.httpx.post", side_effect=post):
            result = self.invoke_graph()

        self.assertEqual(len(requests), 5)
        self.assertTrue(all(
            execution["output"]["llm"]["used"]
            for execution in result["agent_executions"]
        ))
        self.assertTrue(all(url == "https://api.groq.com/openai/v1/chat/completions" for url, _ in requests))
        self.assertTrue(all(
            kwargs["json"]["response_format"] == {"type": "json_object"}
            and kwargs["json"]["temperature"] == 0.1
            and kwargs["timeout"] == 12
            for _, kwargs in requests
        ))
        self.assertEqual(result["risk_report"]["severity"], "high")
        self.assertTrue(any(
            hypothesis["source"] == "llm"
            for hypothesis in result["correlation"]["hypotheses"]
        ))
        self.assertTrue(all(
            hypothesis["source"] == "rules"
            for hypothesis in result["correlation"]["hypotheses"]
            if hypothesis["pattern"] != "Potential repeated access attempt"
        ))

    def test_groq_failure_uses_rule_report_without_duplicate_recommendations(self):
        with patch.dict(os.environ, {
            "GROQ_API_KEY": "test-key",
            "ABUSEIPDB_API_KEY": "",
            "VT_API_KEY": "",
        }), \
                patch("llm.httpx.post", side_effect=httpx.TimeoutException("timed out")):
            result = self.invoke_graph()

        report = result["risk_report"]
        self.assertEqual(report["severity"], "high")
        self.assertEqual(
            report["recommendations"],
            [
                "Treat the successful authentication as high-priority and isolate or verify the target host and source activity",
                "Review active sessions, privileged actions and post-login activity for the affected account",
                "Review the submitted evidence in the original system context",
                "Preserve source logs and collection timestamps",
                "Connect configured threat intelligence providers before attribution decisions",
            ],
        )
        self.assertEqual(len(report["recommendations"]), len(set(report["recommendations"])))
        self.assertFalse(report["llm"]["used"])
        self.assertIsNone(report["llm"]["result"])


if __name__ == "__main__":
    unittest.main()
