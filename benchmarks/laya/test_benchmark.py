"""Offline checks. No model requests or sample action execution."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import benchmark as B
from corpus import HOSTS, VERDICTS, cases, host_fixture


class BenchmarkTests(unittest.TestCase):
    def test_corpus(self):
        corpus = cases()
        self.assertEqual(len(corpus), 400)
        self.assertEqual(len({c["id"] for c in corpus}), 400)
        self.assertTrue(all(Path(c["id"]).name == c["id"] for c in corpus))
        for verdict in VERDICTS:
            self.assertEqual(sum(c["expected"] == verdict for c in corpus), 100)
        self.assertEqual(len({(c["category"], c["family"]) for c in corpus}), 100)

    def test_native_baselines_and_prompt_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            for case in cases():
                for host in HOSTS:
                    fixture = host_fixture(case, host)
                    baseline = B.baseline(fixture, temp)
                    self.assertIn(baseline["decision"], VERDICTS)
                    normalized = B.normalize(fixture, baseline)
                    if case.get("stale") or case.get("automated"):
                        self.assertEqual(normalized["prompts"], [])
                    else:
                        self.assertEqual([p["text"] for p in normalized["prompts"]],
                                         [p for p in (case["previous"], case["latest"]) if p is not None])
                    if case["expected"] == "block":
                        self.assertEqual(baseline["decision"], "block", case["id"])
                    original = copy.deepcopy(normalized)
                    for context in B.CONTEXTS:
                        a = B.request_for(normalized, context, "forward")
                        b = B.request_for(normalized, context, "reverse")
                        self.assertEqual(a["state"], b["state"])
                        self.assertEqual(list(a["questions"]["verdict"]["criteria"]), list(VERDICTS))
                        self.assertEqual(list(b["questions"]["verdict"]["criteria"]), list(VERDICTS[::-1]))
                        self.assertNotIn("expected", a["state"])
                        self.assertNotIn("label_reason", a["state"])
                    self.assertEqual(original, normalized)

    def test_decode(self):
        body = {"model": "laya-rl-agent", "routing": {"model": "typed-decisions"}, "answers": {"verdict": {"type": "choice", "choice": "run",
                "probabilities": {"run": .4, "log": .2, "review": .2, "block": .2},
                "confidence": .05, "answer_confidence": .4}}, "usage": {"truncated": False}}
        self.assertEqual(B.decode_response(body)["candidate"], "run")
        wrong_route = copy.deepcopy(body)
        wrong_route["routing"]["model"] = "other-model"
        with self.assertRaises(ValueError):
            B.decode_response(wrong_route)
        for field, value in (("choice", "allow"), ("probabilities", {"run": 1}), ("confidence", float("nan"))):
            broken = copy.deepcopy(body)
            broken["answers"]["verdict"][field] = value
            with self.assertRaises((ValueError, KeyError)):
                B.decode_response(broken)
        broken = copy.deepcopy(body)
        broken["answers"]["verdict"]["probabilities"]["run"] = float("nan")
        with self.assertRaises(ValueError):
            B.decode_response(broken)

    def test_curl_transports_json_without_a_shell(self):
        completed = B.subprocess.CompletedProcess([], 0, "\n200 0.01", "")
        with patch.object(B.subprocess, "run", return_value=completed) as execute:
            result = B.curl("http://localhost:8601/v1/systemone", Path("request.json"),
                            Path("response.json"), Path("headers.txt"))
        command = execute.call_args.args[0]
        self.assertEqual(command[:2], ["curl", "--disable"])
        self.assertEqual(command[command.index("--data-binary") + 1], "@request.json")
        self.assertFalse(execute.call_args.kwargs.get("shell", False))
        self.assertEqual(result["http_status"], 200)

    def test_metric_exclusions_and_clearances(self):
        labels = {"a": {"expected": "review", "scorable": True}, "b": {"expected": "run", "scorable": True}}
        rows = [{"case_id": "a", "candidate": "run", "original": "review", "selected_probability": .4},
                {"case_id": "b", "candidate": "run", "original": "review", "selected_probability": .6},
                {"case_id": "a", "candidate": "run", "original": "review", "selected_probability": .9, "truncated": True},
                {"case_id": "a", "error": "timeout"}]
        metrics = B.metrics(rows, labels)
        self.assertEqual(metrics["scored"], 2)
        self.assertEqual(metrics["unsafe_clearances"], 1)
        self.assertEqual(metrics["unsafe_continuations"], 1)
        self.assertEqual(metrics["justified_clearances"], 1)
        self.assertEqual(metrics["errors"], 1)
        self.assertEqual(metrics["accuracy_pct"], 50)

    def test_report_and_frozen_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "run"
            B.prepare(out)
            manifest = B.verify_frozen(out)
            self.assertEqual(len(manifest["tasks"]), 7200)
            (out / "results.jsonl").write_text("", encoding="utf-8")
            B.report(out)
            summary = json.loads((out / "summary.json").read_text())
            self.assertFalse(summary["complete"])
            self.assertEqual(summary["total"]["scored"], 0)
            path = out / "requests" / (manifest["tasks"][0]["id"] + ".json")
            path.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                B.verify_frozen(out)


if __name__ == "__main__":
    unittest.main()
