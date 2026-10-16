# Laya benchmark result

The benchmark completed on October 10, 2026 UTC.
It sent 7,200 curl requests to the typed-decisions checkpoint.
The test contains 400 synthetic cases in 100 action families.
The cases reuse 88 distinct tool actions.
The test covers Codex, Claude Code, and Hermes fixture contracts.
The assistant assigned the reference labels before inference.

## Main result

Do not give this configuration authority to replace review or block decisions.
The current gate and its approvals remain unchanged.

| Conversation context | Scored predictions | Accuracy |
| --- | ---: | ---: |
| No prompts | 2,376 | 73.74% |
| Latest user prompt | 2,376 | 63.43% |
| Latest two user prompts | 2,364 | 62.44% |

All variants use the same full-context reference labels.
The no-prompt variant cannot know user restrictions.
These results apply to this request format and this reference policy.
They do not prove that conversation context always reduces model quality.

## Decision changes with two prompts

The original-review subset has 424 scored predictions.
Laya proposed automatic continuation on 161 predictions.
The reference policy permits 95 of those clearances.
The reference policy rejects the other 66 clearances.

The protected-file subset has 600 scored predictions.
Laya chose block on only 107 predictions.
Laya chose run or log on 244 predictions.
Laya chose review on the other 249 predictions.
The current gate still blocks all protected-file fixtures.

Option reversal changed 799 of 3,558 comparable predictions, or 22.46%.
The same-action intent pairs show limited context use.
Two prompts produced both correct decisions on 32 of 234 pairs, or 13.68%.
No prompts produced both correct decisions on zero pairs.

## Reliability

The run had zero HTTP failures after all 7,200 calls.
The runner preserved 12 initial local decoder errors and corrected them from saved responses.
The correction did not repeat HTTP requests or change the frozen policy.
The API root model field names the architecture.
The routing field identifies the typed-decisions checkpoint.

The token audit confirms that all instruction and option text fits.
The run contains 12 requests with state truncation.
The run contains 72 ambiguous request variants.
The accuracy excludes those requests.

The median HTTP latency is 26.54 ms.
The 95th percentile is 32.20 ms.
The maximum is 579.21 ms.
Another model process shares the RTX 3090.
These measurements do not represent isolated hardware capacity.

## Evidence and limits

The checkpoint SHA-256 is:

```text
4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e
```

The server uses Laya 0.4.0, Transformers 5.17.0, and PyTorch 2.13.0.
The full local report includes exact inputs, raw responses, errors, confidence bins, and confusion matrices.
Git ignores raw results because their metadata contains private endpoint and checkpoint paths.

- [Full local report](results/intent-v1/REPORT.md)
- [Machine-readable summary](results/intent-v1/summary.json)
- [Raw results](results/intent-v1/results.jsonl)
- [CSV results](results/intent-v1/results.csv)
- [Frozen request manifest](results/intent-v1/manifest.json)
- [Procedure](README.md)

The assistant authored the labels. No independent person checked them.
The fixtures are synthetic, not captures from live CLI sessions.
Repeated predictions are not independent scenarios.
No fine-tune occurred. The benchmark alone cannot establish whether a fine-tune will solve the errors.

Skipped: live hook installation, live CLI capture, and automatic enforcement changes.
Risk: the current HTTP endpoint has no encryption or authentication. Use only synthetic, non-secret inputs.
