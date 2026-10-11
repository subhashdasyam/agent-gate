# Agent Gate decision-model pilot

This pilot adapts the original Laya decision heads to Agent Gate tasks.
It predicts a gate verdict and user intent as separate typed choices.
It does not change production enforcement.
Both questions use Laya's shared native choice head. The pilot does not add separate classifier layers for each question.

Refer to the [measured pilot results](RESULTS.md) before you use the checkpoint.

## Dataset

The dataset contains 2,000 synthetic cases and 4,000 labeled decisions.
It includes Codex, Claude Code, and Hermes fixtures.
The verdict options are `run`, `log`, `review`, and `block`.
The intent options are `matches`, `conflicts`, and `unclear`.

Each input contains the latest two valid user prompts, the proposed action, trusted context, and current Gate facts.
Labels and label reasons stay outside the input.
Protected Gate access always receives the `block` label.
An intent match does not remove a policy risk.
The reference policy permits requested, harmless inline arithmetic.

The input includes the current Gate verdict.
Thus, a correct protected-file answer does not prove that the model can identify protected access without Gate facts.

The dataset has 200 distinct actions in 200 scenario families.
Forty operation-template groups each contain five subject variants.
Each family contains ten user-context variants: requests, prohibitions, follow-ups, pasted text, and missing context.

Whole templates stay in one split:

| Split | Cases |
|---|---:|
| Train | 1,400 |
| Validation | 200 |
| Calibration | 200 |
| Final test | 200 |

The assistant assigned the labels before inference.
The labels are not independent human ground truth.
Prompt patterns recur across splits. The 2,000 cases are not 2,000 independent tasks.

## Procedure

Use the installed Gate parser runtime to create the dataset:

```bash
GATE_PILOT_PYTHON="$(python3 -c 'from adapters.bootstrap import check_runtime; print(check_runtime())')"
"$GATE_PILOT_PYTHON" -m unittest discover -s benchmarks/laya/pilot -p 'test_*.py'
"$GATE_PILOT_PYTHON" benchmarks/laya/pilot/dataset.py benchmarks/laya/results/pilot-example \
  --regression benchmarks/laya/results/intent-v1
```

Omit `--regression` if the previous raw benchmark is unavailable.
The builder refuses an output directory that already exists.
It records hashes, label counts, host counts, and a 40-case label sample.
Sample actions remain data. The builder does not execute them.

Copy `run.py` and the dataset files to a new experiment directory on the GPU host.
Use the installed Laya environment to run the experiment:

```bash
/absolute/path/to/venv/bin/python -u run.py \
  /absolute/path/to/data /absolute/path/to/typed-decisions /absolute/path/to/new-output
```

The runner copies the source checkpoint before a native loader can repair its tokenizer files.
The runner uses offline mode. It does not download a model or change a service.
It does not connect the new checkpoint to Agent Gate.

The recipe uses frozen encoder weights, eight epochs, and supervised soft cross-entropy.
It shuffles choice options and their targets together.
It uses BF16, micro-batch 2, gradient accumulation 16, and head learning rate `1e-4`.
The effective batch contains at most 32 labeled decisions.

If the native train stage exceeds GPU memory, it retries with micro-batch 1 and accumulation 32.
It preserves the incomplete checkpoint. A second memory failure stops the experiment.

The token audit rejects clipped pilot inputs or question text.
The smoke check requires finite loss, head gradients, and no encoder gradients.
Final weight hashes must confirm an unchanged encoder and changed decision heads.

## Evaluation

The runner compares unchanged Laya, the trained pilot, and current Gate on identical final-test inputs.
It records accuracy, macro-F1, confusion matrices, unsafe continuations, protected-file decisions, intent pairs, and option-order stability.
Current Gate has no semantic intent head. Its intent metric remains unavailable.
The latency measurement uses warm in-process inference, not HTTP or a complete hook call.

The calibration split contains 400 choice decisions.
That quantity cannot support native per-bucket calibration, which needs at least 2,000 records.
The separate calibration file uses the type-level fallback.
Do not use these confidence values to grant approval.

Load the final checkpoint and its calibration together:

```python
import laya

agent = laya.load("/absolute/path/to/checkpoint", device="cuda",
                  calibration="/absolute/path/to/checkpoint/calibration.json")
```

Create the report from saved local evidence:

```bash
python3 benchmarks/laya/pilot/report.py \
  /absolute/path/to/data /absolute/path/to/experiment benchmarks/laya/pilot/RESULTS.md
```

The previous benchmark remains a regression set, not fresh test evidence.
The frozen recipe does not select settings from the final test.
A failed pilot remains a valid experiment result, not a production candidate.

Source: [Native Laya fine-tune procedure](https://github.com/NandhaKishorM/laya/blob/main/docs/finetune.md).

Skipped: new dependencies, new services, model downloads, and production integration.
Risk: assistant labels and repeated prompt patterns can overstate quality. Independent traces and labels remain necessary.
