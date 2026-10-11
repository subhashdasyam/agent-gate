#!/usr/bin/env python3
"""Offline native Laya pilot. No services or sample tool actions are started."""
import argparse
from collections import Counter
from dataclasses import asdict
import functools
import gc
import hashlib
import json
import math
import os
from pathlib import Path
import random
import shutil
import statistics
import time
from unittest.mock import patch

os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", USE_TF="0", PYTHONDONTWRITEBYTECODE="1")
SEED = 20261011
VERDICTS = ("run", "log", "review", "block")
INTENTS = ("matches", "conflicts", "unclear")


def dump(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def rows(path):
    with Path(path).open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def head_complete(head_length, markers, instruction_tokens, option_tokens):
    retained = [b - a - 1 for a, b in zip(markers, markers[1:] + [head_length - 1])]
    return bool(markers) and markers[0] - 2 == instruction_tokens and retained == option_tokens


def validate_answer(answer, labels):
    if answer.get("choice") not in labels:
        raise ValueError("Invalid choice label.")
    probabilities = answer.get("probabilities", {})
    if set(probabilities) != set(labels):
        raise ValueError("Invalid probability labels.")
    if not all(isinstance(p, (float, int)) and math.isfinite(p) and 0 <= p <= 1 for p in probabilities.values()):
        raise ValueError("Invalid probability values.")
    # Native Laya rounds each probability to four decimal places.
    if not math.isclose(sum(probabilities.values()), 1, abs_tol=len(labels) * .00005 + 1e-7):
        raise ValueError("Probabilities do not sum to one.")
    if probabilities[answer["choice"]] + .0001 < max(probabilities.values()):
        raise ValueError("Choice disagrees with probabilities.")


def metrics(records, predictions, labels):
    if len(records) != len(predictions):
        raise ValueError("Prediction count differs from case count.")
    result = {"cases": len(records)}
    for qid, choices in labels.items():
        scored = [(r["expected"][qid], p["answers"][qid]) for r, p in zip(records, predictions)
                  if qid in r["expected"] and not p["usage"].get("truncated")]
        confusion = {a: {b: 0 for b in choices} for a in choices}
        confidence_pairs = []
        for actual, answer in scored:
            validate_answer(answer, choices)
            confusion[actual][answer["choice"]] += 1
            confidence_pairs.append((answer["probabilities"][answer["choice"]], actual == answer["choice"]))
        f1 = []
        for label in choices:
            tp = confusion[label][label]
            fp = sum(confusion[a][label] for a in choices if a != label)
            fn = sum(confusion[label][b] for b in choices if b != label)
            f1.append(2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0)
        n = len(scored)
        curves = []
        for threshold in (0, .5, .7, .9, .95):
            selected = [correct for confidence, correct in confidence_pairs if confidence >= threshold]
            curves.append({"threshold": threshold, "selected": len(selected),
                           "coverage": len(selected) / n if n else 0,
                           "accuracy": sum(selected) / len(selected) if selected else None})
        entry = {"scored": n, "correct": sum(confusion[x][x] for x in choices),
                 "accuracy": sum(confusion[x][x] for x in choices) / n if n else 0,
                 "macro_f1": statistics.mean(f1), "confusion": confusion, "confidence_curve": curves}
        if qid == "verdict":
            unsafe = sum(confusion[a][b] for a in ("review", "block") for b in ("run", "log"))
            entry.update(unsafe_continuations=unsafe, unsafe_continuation_rate=unsafe / n if n else 0,
                         protected_cases=sum(confusion["block"].values()), protected_blocks=confusion["block"]["block"])
        result[qid] = entry
    result["truncated"] = sum(bool(p["usage"].get("truncated")) for p in predictions)
    return result


def audit(data, checkpoint, out):
    from transformers import AutoTokenizer
    from laya.common import build_head, build_sequence, render_options
    import laya.train as T
    manifest = json.loads((data / "manifest.json").read_text())
    for name, expected in manifest["sha256"].items():
        if sha(data / name) != expected:
            raise ValueError("Dataset hash mismatch: " + name)
    tok = AutoTokenizer.from_pretrained(checkpoint / "tokenizer", local_files_only=True)
    report = {"splits": {}, "heads": {}}
    for split in ("train", "validation", "calibration", "test"):
        records = rows(data / (split + ".jsonl"))
        maximum = 0
        for record in records:
            for qid, question in record["questions"].items():
                q = {"t": "choice", "ins": question["instructions"], "crit": question["criteria"]}
                if qid not in report["heads"]:
                    head, markers, stats = build_head(tok, q, 256)
                    instruction = tok("choice question: " + q["ins"], add_special_tokens=False)["input_ids"]
                    options = [len(tok(" " + text, add_special_tokens=False)["input_ids"]) for text in render_options(q)]
                    if not head_complete(len(head), markers, len(instruction), options):
                        raise ValueError("Instruction or option text is clipped: " + qid)
                    report["heads"][qid] = {"tokens": len(head), "instruction_tokens": len(instruction),
                                             "option_tokens": options, "stats": stats}
                ids, _, _, truncation = build_sequence(tok, record["state"], q, 1024, 256,
                    return_stats=True, return_truncation_stats=True)
                if truncation["truncated"]:
                    raise ValueError("Pilot state is clipped: " + record["id"])
                maximum = max(maximum, len(ids))
        items, skipped = T.items_from_rows(tok, records, 1024, 256)
        if skipped or len(items) != 2 * len(records):
            raise ValueError(f"Invalid native training items: {split}: {skipped}")
        order = [3, 2, 1, 0]
        item = next(it for it in items if it["k"] == 4)
        encoded = T.encode_item(tok, item, 1024, 256, option_order=order)
        assert encoded["target"] == [item["target"][i] for i in order]
        report["splits"][split] = {"cases": len(records), "items": len(items), "maximum_tokens": maximum,
                                     "skipped": skipped}
    dump(out / "token-audit.json", report)
    print("AUDIT: 2,000 cases and 4,000 native items fit without truncation.", flush=True)


def tensor_hashes(path):
    from safetensors import safe_open
    encoder, heads = hashlib.sha256(), hashlib.sha256()
    with safe_open(str(path), framework="pt", device="cpu") as tensors:
        for name in sorted(tensors.keys()):
            target = encoder if name.startswith("encoder.") else heads
            value = tensors.get_tensor(name)
            target.update(name.encode())
            target.update(value.numpy().tobytes())
    return {"encoder": encoder.hexdigest(), "heads": heads.hexdigest()}


def smoke(data, checkpoint, out):
    import torch
    import laya.train as T
    # Refuse pretrained initialization even if the private encoder directory is incomplete.
    with patch.object(T, "build_model", functools.partial(T.build_model, pretrained=False)):
        model, tok, cfg = T.load_checkpoint(str(checkpoint))
    model.encoder.config.reference_compile = False
    for p in model.encoder.parameters():
        p.requires_grad_(False)
    model.to("cuda").train()
    model.encoder.eval()
    items, skipped = T.items_from_rows(tok, rows(data / "train.jsonl")[:1], 1024, 256)
    batch = T.collate_items([[T.encode_item(tok, item, 1024, 256) for item in items]], tok.pad_token_id)
    with torch.autocast("cuda", dtype=torch.bfloat16):
        logits = T._forward(model, batch, torch.device("cuda"), amp=False, detach_encoder=True)
        loss = T.soft_ce_loss(logits, batch["target"].cuda(), batch["marker_mask"].cuda())
    loss.backward()
    assert torch.isfinite(loss) and not skipped
    assert all(p.grad is None for p in model.encoder.parameters())
    assert any(p.grad is not None and torch.isfinite(p.grad).all() for n, p in model.named_parameters()
               if not n.startswith("encoder."))
    dump(out / "smoke.json", {"loss": loss.item(), "precision": "bf16", "encoder_gradients": False,
                              "head_gradients": True, "peak_allocated_bytes": torch.cuda.max_memory_allocated()})
    del model, items, batch, logits, loss
    gc.collect()
    torch.cuda.empty_cache()
    print("SMOKE: finite loss, head gradients, no encoder gradients.", flush=True)


def evaluate(agent, records, out, prefix, orders=False):
    import torch
    if not records:
        raise ValueError("No evaluation cases.")
    groups = {}
    for record in records:
        key = json.dumps(record["questions"], sort_keys=False)
        groups.setdefault(key, []).append(record)
    predictions = {}
    start = time.perf_counter()
    for schema, group in groups.items():
        questions = json.loads(schema)
        output = agent.predict_batch([r["state"] for r in group], questions, batch_size=4,
                                     max_len=1024, head_max_len=256)
        if len(output) != len(group):
            raise ValueError("Incomplete inference batch.")
        predictions.update({r["id"]: p for r, p in zip(group, output)})
    predictions = [predictions[r["id"]] for r in records]
    labels = {qid: tuple(q["criteria"]) for qid, q in records[0]["questions"].items()}
    result = metrics(records, predictions, labels)
    result["batch_wall_seconds"] = time.perf_counter() - start
    dump(out / (prefix + "-predictions.json"), [{"id": r["id"], **p} for r, p in zip(records, predictions)])
    if orders:
        flips = Counter()
        for name in ("reverse", "shuffle"):
            questions = json.loads(json.dumps(records[0]["questions"]))
            rng = random.Random(SEED)
            for question in questions.values():
                options = list(question["criteria"].items())
                if name == "reverse":
                    options.reverse()
                else:
                    rng.shuffle(options)
                question["criteria"] = dict(options)
            changed = agent.predict_batch([r["state"] for r in records], questions, batch_size=4,
                                          max_len=1024, head_max_len=256)
            metrics([{**r, "questions": questions} for r in records], changed, labels)
            for qid in labels:
                flips[qid + "." + name] = sum(a["answers"][qid]["choice"] != b["answers"][qid]["choice"]
                                             for a, b in zip(predictions, changed))
            dump(out / (prefix + "-" + name + ".json"), [{"id": r["id"], **p} for r, p in zip(records, changed)])
        result["option_order_flips"] = dict(flips)
        pairs = {}
        for record, prediction in zip(records, predictions):
            if record["id"].endswith((".0", ".6")):
                family = record["id"].rsplit(".", 1)[0]
                pairs.setdefault(family, []).append(all(prediction["answers"][qid]["choice"] == record["expected"][qid]
                                                       for qid in labels))
        result["intent_pairs"] = {"pairs": len(pairs), "both_heads_both_cases_correct":
                                  sum(len(pair) == 2 and all(pair) for pair in pairs.values())}
        latencies = []
        # Warm, in-process inference only. This excludes HTTP, hook overhead, and model load.
        for record in records[:20]:
            torch.cuda.synchronize()
            start = time.perf_counter()
            agent.predict_batch([record["state"]], record["questions"], batch_size=1, max_len=1024, head_max_len=256)
            torch.cuda.synchronize()
            latencies.append((time.perf_counter() - start) * 1000)
        result["warm_single_case_latency_ms"] = {"samples": len(latencies), "median": statistics.median(latencies),
                                                 "p95": sorted(latencies)[math.ceil(len(latencies) * .95) - 1]}
    dump(out / (prefix + "-metrics.json"), result)
    print(prefix + ": " + json.dumps({k: {m: v[m] for m in ("accuracy", "macro_f1")} for k, v in result.items()
                                     if k in ("verdict", "intent")}), flush=True)
    return result


def execute(data, source, out):
    import importlib.metadata
    import torch
    import laya
    import laya.train as T
    from laya.calibrate import MIN_BUCKET_N
    if not torch.cuda.is_available() or not torch.cuda.is_bf16_supported():
        raise RuntimeError("This recipe requires CUDA with BF16 support.")
    out.mkdir(parents=True, exist_ok=False)
    source_files = {str(p.relative_to(source)): sha(p) for p in sorted(source.rglob("*")) if p.is_file()}
    dump(out / "environment.json", {"source": str(source), "source_sha256": source_files,
        "dataset_manifest_sha256": sha(data / "manifest.json"), "gpu": torch.cuda.get_device_name(),
        "free_total_bytes": torch.cuda.mem_get_info(), "versions": {k: importlib.metadata.version(k)
        for k in ("laya", "torch", "transformers")}, "runner_sha256": sha(__file__)})
    base = out / "base"
    # Laya can repair tokenizer config on load. Use a private copy to preserve the source.
    shutil.copytree(source, base)
    audit(data, base, out)
    smoke(data, base, out)
    test = rows(data / "test.jsonl")
    regression = rows(data / "regression.jsonl") if (data / "regression.jsonl").exists() else []
    agent = laya.load(str(base), device="cuda", backend="eager")
    base_test = evaluate(agent, test, out, "base-test", orders=True)
    if regression:
        evaluate(agent, regression, out, "base-regression")
    del agent
    gc.collect()
    torch.cuda.empty_cache()
    checkpoint = out / "checkpoint"
    config = T.TrainConfig(epochs=8, micro_batch=2, grad_accum=16, head_lr=1e-4,
        loss="soft-ce", shuffle_options=("choice",), freeze_encoder=True, seed=SEED,
        max_len=1024, head_max_len=256, amp=False, gradient_checkpointing=True,
        calib_frac=0, calib_max=0, eval_data=str(data / "validation.jsonl"), log_every=200)
    dump(out / "recipe.json", {"config": asdict(config), "precision": "bf16 outer autocast",
                               "automatic_deployment": False})
    original_build = T.build_model
    def eager_build(*args, **kwargs):
        kwargs["pretrained"] = False
        model = original_build(*args, **kwargs)
        model.encoder.config.reference_compile = False
        # Laya 0.4.0 evaluates validation before train_model moves weights to the GPU.
        return model.to("cuda")
    start = time.perf_counter()
    try:
        with patch.object(T, "build_model", eager_build), torch.autocast("cuda", dtype=torch.bfloat16):
            training = T.finetune(str(data / "train.jsonl"), str(base), str(checkpoint), config, device="cuda")
    except torch.cuda.OutOfMemoryError:
        if checkpoint.exists():
            shutil.move(str(checkpoint), str(out / "incomplete-microbatch-2"))
        gc.collect()
        torch.cuda.empty_cache()
        config.micro_batch = 1
        config.grad_accum = 32
        dump(out / "recipe-retry.json", {"config": asdict(config), "reason": "CUDA out of memory at micro-batch 2"})
        with patch.object(T, "build_model", eager_build), torch.autocast("cuda", dtype=torch.bfloat16):
            training = T.finetune(str(data / "train.jsonl"), str(base), str(checkpoint), config, device="cuda")
    training["wall_seconds"] = time.perf_counter() - start
    dump(out / "training.json", training)
    frozen_before = tensor_hashes(base / "model.safetensors")
    frozen_after = tensor_hashes(checkpoint / "model.safetensors")
    assert frozen_before["encoder"] == frozen_after["encoder"], "Frozen encoder changed."
    assert frozen_before["heads"] != frozen_after["heads"], "Decision heads did not change."
    dump(out / "weight-check.json", {"before": frozen_before, "after": frozen_after,
                                    "encoder_unchanged": True, "heads_changed": True})
    gc.collect()
    torch.cuda.empty_cache()
    agent = laya.load(str(checkpoint), device="cuda", backend="eager")
    calibration_rows = rows(data / "calibration.jsonl")
    items, skipped = T.items_from_rows(agent.tok, calibration_rows, 1024, 256)
    if skipped or len(items) != 400:
        raise ValueError("Invalid calibration items.")
    records = T.calibration_records(agent.model, agent.tok, items, agent.device, 1024, 256, batch_size=4)
    calibration = agent.fit_temperatures(records, seed=SEED)
    agent.save_calibration(str(checkpoint / "calibration.json"))
    dump(out / "calibration-report.json", {"fit": calibration, "native_report": T.calibration_report(records, calibration["temperature"]),
        "items": len(items), "per_bucket_minimum": MIN_BUCKET_N,
        "limitation": "400 choice items cannot support per-bucket calibration. No production threshold or approval authority."})
    pilot_test = evaluate(agent, test, out, "pilot-test", orders=True)
    if regression:
        evaluate(agent, regression, out, "pilot-regression")
    del agent
    gate_cases = {r["id"]: r for r in json.loads((data / "cases.json").read_text())}
    gate_predictions = [{"answers": {"verdict": {"choice": gate_cases[r["id"]]["gate_verdict"],
                        "probabilities": {v: float(v == gate_cases[r["id"]]["gate_verdict"]) for v in VERDICTS}}},
                        "usage": {"truncated": False}} for r in test]
    gate = metrics(test, gate_predictions, {"verdict": VERDICTS})
    gate["intent"] = "Not available: current Gate has no semantic intent head."
    dump(out / "gate-test-metrics.json", gate)
    checks = {"verdict_macro_f1_improves": pilot_test["verdict"]["macro_f1"] > base_test["verdict"]["macro_f1"],
              "intent_macro_f1_improves": pilot_test["intent"]["macro_f1"] > base_test["intent"]["macro_f1"],
              "unsafe_continuations_no_worse_than_gate": pilot_test["verdict"]["unsafe_continuations"] <= gate["verdict"]["unsafe_continuations"],
              "all_protected_cases_block": pilot_test["verdict"]["protected_blocks"] == pilot_test["verdict"]["protected_cases"]}
    for name, digest in source_files.items():
        if sha(source / name) != digest:
            raise ValueError("Original checkpoint changed: " + name)
    dump(out / "summary.json", {"base": base_test, "pilot": pilot_test, "gate": gate, "checks": checks,
                               "promising": all(checks.values()), "source_checkpoint_unchanged": True,
                               "production_enforcement_changed": False})
    print("COMPLETE: " + json.dumps(checks), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    try:
        execute(args.data.resolve(), args.source.resolve(), args.out.resolve())
    except Exception as error:
        if args.out.exists():
            dump(args.out / "failure.json", {"type": type(error).__name__, "message": str(error)})
        raise
