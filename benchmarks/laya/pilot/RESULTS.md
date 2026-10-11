# Agent Gate decision-model pilot

## Result

The pilot did not pass all four comparison checks. Do not use it for production enforcement.

The experiment did not change production enforcement or the original checkpoint.
The experiment did not execute any sample tool action.

## Fresh held-out test

The final test contains 200 cases from four operation-template groups.
These templates do not occur in the train, validation, or calibration splits.

| Candidate | Verdict accuracy | Verdict macro-F1 | Intent accuracy | Intent macro-F1 | Unsafe continuations | Protected blocks |
|---|---:|---:|---:|---:|---:|---:|
| gate | 80.0% | 0.804 | Not available | Not available | 40 | 50/50 |
| base | 64.0% | 0.636 | 64.5% | 0.383 | 39 | 13/50 |
| pilot | 84.0% | 0.850 | 94.0% | 0.936 | 18 | 39/50 |

An unsafe continuation is a run or log prediction where the reference label requires review or block.
The Gate baseline has no semantic intent head. Its intent score is not zero.
The pilot adds 0 unsafe cases that Gate does not continue automatically.

The pilot chose review for 11 protected cases, not run or log.

| Comparison check | Result |
|---|---|
| verdict macro f1 improves | Pass |
| intent macro f1 improves | Pass |
| unsafe continuations no worse than gate | Pass |
| all protected cases block | Fail |

## Dataset and recipe

The dataset contains 2000 synthetic cases and 4000 labeled decisions.
The dataset has 200 distinct actions, 200 scenario families, and 40 operation-template groups.
Five subject variants share each template. Ten user-context variants share each action.
Whole templates stay in one split. Prompt patterns recur across splits.

| Split | Cases |
|---|---:|
| train | 1400 |
| validation | 200 |
| calibration | 200 |
| test | 200 |

The assistant assigned all reference labels before inference.
These labels are not independent human ground truth.
Each input includes the original Gate verdict. Protected-file accuracy does not measure independent detection without those Gate facts.

The verdict counts are run: 300, review: 900, log: 300, block: 500.

The intent counts are matches: 1200, conflicts: 400, unclear: 400.

The host counts are codex: 670, claude: 670, hermes: 660.

The recipe uses eight epochs, frozen encoder weights, soft cross-entropy, and shuffled choice options.
The effective batch contains at most 32 labeled decisions. The head learning rate is 0.0001.
The native trainer runs inside a BF16 autocast context. It does not use an FP16 gradient scaler.

The run took 6.4 minutes for the native train and validation stages.
The epoch losses are `0.8388, 0.7544, 0.6145, 0.5059, 0.4468, 0.3914, 0.3696, 0.3704`.
The weight hashes confirm that the encoder did not change and the decision heads changed.
The token audit found no clipped pilot input or question text.

## Calibration and stability

The calibration split contains 200 cases and 400 choice decisions.
This quantity is less than the native minimum of 2,000 records per option-count bucket.
The calibration fit uses the type-level fallback. It does not establish a safe approval threshold.
The original checkpoint has an out-of-range temperature. Native Laya clamps that value on load.

| Candidate | Intent pairs correct | Verdict flips, reverse | Verdict flips, shuffle | Intent flips, reverse | Intent flips, shuffle |
|---|---:|---:|---:|---:|---:|
| base | 0/20 | 39 | 10 | 4 | 6 |
| pilot | 12/20 | 27 | 20 | 11 | 20 |

Each intent pair contains the same action with an explicit request and a later prohibition.
A correct pair requires both typed questions to answer both cases correctly.
Both questions use the shared native choice head. Separate metrics do not imply separate classifier parameters.
The order check uses canonical, reverse, and one seeded shuffled order. It does not cover every permutation.

## Warm latency

| Candidate | Median | P95 | Samples |
|---|---:|---:|---:|
| base | 30.01 ms | 33.04 ms | 20 |
| pilot | 30.18 ms | 33.25 ms | 20 |

Latency uses warm, in-process, two-question inference on a shared GPU.
The measurement excludes model load, HTTP, and hook overhead.
It is not directly comparable with the previous HTTP benchmark or Gate classification time.

## Existing benchmark regression

The previous benchmark is an exposed regression set, not fresh proof of generalization.
The comparison excludes stale-session cases and clipped states from accuracy.
The three context variants use the same action cases. They are not independent samples.

| Context | Candidate | Correct/scored | Accuracy | Unsafe continuations | Protected blocks |
|---|---|---:|---:|---:|---:|
| none | gate | 2032/2376 | 85.5% | 248 | 600/600 |
| none | base | 1751/2376 | 73.7% | 264 | 381/600 |
| none | pilot | 1389/2376 | 58.5% | 56 | 522/600 |
| latest | gate | 2032/2376 | 85.5% | 248 | 600/600 |
| latest | base | 1506/2376 | 63.4% | 556 | 93/600 |
| latest | pilot | 1525/2376 | 64.2% | 100 | 364/600 |
| two | gate | 2026/2364 | 85.7% | 242 | 600/600 |
| two | base | 1472/2364 | 62.3% | 527 | 107/600 |
| two | pilot | 1521/2364 | 64.3% | 109 | 353/600 |

Overall regression accuracy fell from 66.5% to 62.3%.
The largest decrease occurs with no user prompt. The pilot often requests review when context is missing.
With two prompts, verdict accuracy rises slightly but remains much less than the Gate baseline.

## Evidence and limits

The local raw results contain the dataset manifest, token audit, recipe, logs, predictions, errors, and calibration report.
The remote checkpoint directory contains the final weights, question definitions, tokenizer, and separate calibration file.
Load the calibration file with the checkpoint. The checkpoint alone does not apply the separate fit.

The initial attempt stopped before the train stage because a probability-sum check did not account for the native decimal precision.
The corrected check permits only the maximum four-decimal precision error. A regression test covers that case.

The second attempt stopped before its first update because native validation used GPU inputs with CPU weights.
The experiment runner moves the private model to the GPU before native validation. The installed package remains unchanged.

Next, collect independent labels and diverse real hook traces. Keep deterministic protected-file blocks and use the model only for shadow comparisons.

The reload check reproduced 16 typed answers from 8 cases with the separate calibration file.

The original Laya service remained healthy after the experiment. Its process did not change.
The offline checks passed: 6 pilot tests, 6 benchmark tests, 20 plugin tests, 54 core checks, 128 adapter checks.

The probe corpus caught all 318 inert probes. Normal mode reviewed zero of 87 clean cases, and strict mode reviewed two.

Skipped: live CLI capture, production deployment, encoder adaptation, and model downloads.
Risk: synthetic labels and a 200-case test cannot establish production safety.
