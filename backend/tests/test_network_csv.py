import tempfile
import unittest
from pathlib import Path

import pandas as pd

from csv_loader import GROUND_TRUTH_COLUMNS, load_network_flow_sample
from graph import build_investigation_graph


class NetworkCSVIntegrationTest(unittest.TestCase):
    def test_default_sample_is_bounded_and_ground_truth_columns_are_removed(self):
        loaded = load_network_flow_sample(row_count=25)

        self.assertEqual(loaded["row_count"], 25)
        self.assertLessEqual(loaded["row_count"], 100)
        self.assertEqual(set(loaded["labels_removed"]), {"Label", "ClassLabel"})
        self.assertFalse(GROUND_TRUTH_COLUMNS.intersection(loaded["feature_columns"]))
        self.assertTrue(all(
            not GROUND_TRUTH_COLUMNS.intersection(record.keys())
            for record in loaded["records"]
        ))

    def test_invalid_and_empty_csv_are_rejected_safely(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            invalid_path = directory_path / "invalid.csv"
            invalid_path.write_text("", encoding="utf-8")

            with self.assertRaises(ValueError):
                load_network_flow_sample(row_count=10, csv_path=invalid_path)

            empty_path = directory_path / "empty.csv"
            pd.DataFrame(columns=["Flow Duration", "Label", "ClassLabel"]).to_csv(empty_path, index=False)
            loaded = load_network_flow_sample(row_count=10, csv_path=empty_path)

            self.assertEqual(loaded["row_count"], 0)
            self.assertEqual(loaded["feature_count"], 0)
            self.assertIn("Label", loaded["labels_removed"])
            self.assertIn("ClassLabel", loaded["labels_removed"])

    def test_network_records_reach_agents_without_ground_truth_labels(self):
        loaded = load_network_flow_sample(row_count=20)
        graph = build_investigation_graph()
        result = graph.invoke({
            "investigation_id": "network-regression",
            "prompt": "Analyze a bounded network-flow sample",
            "evidence": [],
            "agent_executions": [],
            "triage": {},
            "threat_intelligence": {},
            "log_analysis": {},
            "correlation": {},
            "risk_report": {},
            "report_status": "in_progress",
            "network_records": loaded["records"],
            "network_dataset": loaded,
        })

        self.assertEqual(result["log_analysis"]["network_summary"]["record_count"], 20)
        self.assertFalse(any(
            "Label" in record or "ClassLabel" in record
            for record in result["network_records"]
        ))
        serialized = repr(result)
        self.assertNotIn("'Label'", serialized)
        self.assertNotIn("'ClassLabel'", serialized)


if __name__ == "__main__":
    unittest.main()
