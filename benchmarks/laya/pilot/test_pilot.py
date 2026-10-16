"""Offline pilot checks. No sample tool action is executed."""
import json
from pathlib import Path
import tempfile
import unittest

import dataset as D
import run as R
import report as P


class PilotTests(unittest.TestCase):
    def test_counts_and_group_isolation(self):
        rows = D.cases()
        D.validate(rows)
        self.assertEqual({r["expected"] for r in rows}, set(D.VERDICTS))
        self.assertEqual({r["intent"] for r in rows}, set(D.INTENTS))
        for split in D.SIZES:
            self.assertEqual({r["category"] for r in rows if r["split"] == split}, set(D.VERDICTS))

    def test_intent_pairs_and_protection(self):
        rows = D.cases()
        for family in {r["family"] for r in rows}:
            group = [r for r in rows if r["family"] == family]
            self.assertEqual(len({json.dumps(r["action"], sort_keys=True) for r in group}), 1)
            self.assertEqual({r["intent"] for r in group}, set(D.INTENTS))
            for row in group:
                if row["category"] == "block":
                    self.assertEqual(row["expected"], "block")
                elif row["intent"] != "matches":
                    self.assertEqual(row["expected"], "review")

    def test_native_export_has_no_label_leak(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "data"
            D.prepare(out)
            labels = {r["id"]: r for r in json.loads((out / "cases.json").read_text())}
            for split, count in D.SIZES.items():
                records = D.B.jsonlines(out / (split + ".jsonl"))
                self.assertEqual(len(records), count)
                for record in records:
                    self.assertNotIn("expected", record["state"])
                    self.assertNotIn("label_reason", record["state"])
                    self.assertNotIn("intent_reason", record["state"])
                    self.assertEqual(record["expected"]["verdict"], labels[record["id"]]["expected"])
            with self.assertRaises(FileExistsError):
                D.prepare(out)

    def test_probability_validation_and_safety_counts(self):
        records = [{"expected": {"verdict": label}} for label in ("run", "review", "block")]
        predictions = [{"answers": {"verdict": {"choice": label, "probabilities":
            {v: float(v == label) for v in D.VERDICTS}}}, "usage": {"truncated": False}}
            for label in ("run", "run", "block")]
        report = R.metrics(records, predictions, {"verdict": D.VERDICTS})
        self.assertEqual(report["verdict"]["unsafe_continuations"], 1)
        self.assertEqual(report["verdict"]["protected_blocks"], 1)
        self.assertAlmostEqual(report["verdict"]["accuracy"], 2 / 3)
        predictions[1]["usage"]["truncated"] = True
        self.assertEqual(R.metrics(records, predictions, {"verdict": D.VERDICTS})["verdict"]["scored"], 2)
        with self.assertRaises(ValueError):
            R.validate_answer({"choice": "run", "probabilities": {"run": float("nan")}}, D.VERDICTS)
        with self.assertRaises(ValueError):
            R.metrics(records, [], {"verdict": D.VERDICTS})
        R.validate_answer({"choice": "run", "probabilities":
            {"run": .4000, "log": .2000, "review": .2001, "block": .2001}}, D.VERDICTS)
        with self.assertRaises(ValueError):
            R.validate_answer({"choice": "run", "probabilities":
                {"run": .1, "log": .2, "review": .3, "block": .4}}, D.VERDICTS)

    def test_head_audit_rejects_clipped_options(self):
        self.assertTrue(R.head_complete(11, [4, 7], 2, [2, 2]))
        self.assertFalse(R.head_complete(10, [4, 7], 2, [2, 2]))
        self.assertFalse(R.head_complete(11, [4, 7], 3, [2, 2]))

    def test_report_from_saved_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            record = {"id": "pilot.example.renderer.0", "state": {"context": {"host": "codex"}},
                      "expected": {"verdict": "run", "intent": "matches"}}
            prediction = {"id": record["id"], "answers": {qid: {"choice": chosen,
                "probabilities": {v: float(v == chosen) for v in labels}} for qid, chosen, labels in
                (("verdict", "run", D.VERDICTS), ("intent", "matches", D.INTENTS))}, "usage": {"truncated": False}}
            metric = R.metrics([record], [prediction], {"verdict": D.VERDICTS, "intent": D.INTENTS})
            metric.update(option_order_flips={k + "." + o: 0 for k in ("verdict", "intent") for o in ("reverse", "shuffle")},
                          intent_pairs={"pairs": 1, "both_heads_both_cases_correct": 1},
                          warm_single_case_latency_ms={"samples": 1, "median": 1, "p95": 1})
            R.dump(out / "summary.json", {"promising": True, "base": metric, "pilot": metric,
                "gate": {"verdict": metric["verdict"], "intent": "Not available"}, "checks": {"example": True}})
            R.dump(out / "training.json", {"wall_seconds": 1, "epoch_loss": [1, .5]})
            R.dump(out / "cases.json", [{"id": record["id"], "gate_verdict": "run"}])
            R.dump(out / "manifest.json", {"case_count": 2000, "decisions": 4000, "splits": D.SIZES,
                "verdict_counts": {"run": 300}, "intent_counts": {"matches": 1200}, "host_counts": {"codex": 670}})
            for name in ("base", "pilot"):
                R.dump(out / (name + "-test-predictions.json"), [prediction])
            (out / "test.jsonl").write_text(json.dumps(record) + "\n")
            P.build(out, out, out / "report.md")
            self.assertIn("Not available", (out / "report.md").read_text())
            self.assertEqual(json.loads((out / "test-errors.json").read_text()), [])


if __name__ == "__main__":
    unittest.main()
