# Is the RAKSHAK.AI 14B model right for RAKSHAK.VYUH?

**No — and the reason is not size. It is the input.**

Short answer: do not build a smaller model. Build no model.

## What the 14B model actually does

`Muneerali199/rakshak-cwe-14b-sft-final`, read from the model card and its
benchmark file on Hugging Face:

- **Base:** Qwen2.5-Coder-14B-Instruct, LoRA adapter
- **Task:** given a **block of source code**, name the CWE, rate severity, and
  propose a patch
- **Benchmark:** 72 samples of Python, JavaScript, C, Go, Java, Ruby, PHP, Rust
- **Self-reported:** 94.4% vulnerability detection, **27.8% CWE exact accuracy**

### The 94.4% is not a measurement

I recomputed it from the published results. The benchmark holds **68 vulnerable
and 4 clean** samples. A model that answers "vulnerable" to everything scores
`68/72 = 94.44%`.

The model answered `vulnerable = true` on **72 of 72** samples. It never once
said "this is clean".

| | |
|---|---|
| Reported accuracy | 94.44% |
| Base rate of always answering yes | **94.44%** |
| True positive rate (caught all 68 vulnerable) | 100% |
| **True negative rate (cleared any of the 4 clean)** | **0%** |
| Balanced accuracy | 50% — a coin flip |

The headline number is the base rate, reproduced exactly. It carries no
information about the model. Worse, the model has **no ability to say a sample
is safe**, which for a security tool is the failure that matters: every clean
file would be reported as vulnerable.

And the patches are boilerplate in **72 of 72** outputs:

> "The vulnerable code should be rewritten."



## Why it does not transfer to VYUH

**1. It reads code. VYUH reads bytes on a wire.**

The benchmark is 72 vulnerable source functions. Zero of them are packet
captures. Feeding an IKE SA payload to this model gives it text it was never
trained on, and the 27.8% CWE accuracy is the *ceiling* even on its own task.

**2. The one overlapping CWE is a single sample.**

`CWE-327` (broken crypto algorithm) appears **once** in 72 rows. VYUH emits
CWE-327 for a 3DES tunnel. One training example is not a model.

**3. Its patches are boilerplate.**

Reading the raw outputs, the model frequently returns:

> "The vulnerable code should be rewritten."
> "Apply standard security fixes."

A remediation you cannot act on is worse than none, because it looks like an
answer.

**4. 44.8 seconds per sample, on an A10G.**

`avg_time_per_sample_s: 44.82`. VYUH analyses a 20-packet capture in about
**0.1 seconds**. A judge waiting five minutes for one verdict will stop
watching.

**5. It is essentially unvalidated.**

19 downloads, 2 likes, and the benchmark is self-published with no held-out set
and no independent replication.

## The deeper mismatch

VYUH's entire claim is *"every finding is checkable."* A judge opens packet
#1, looks at the SA payload, and reads `ENCR_3DES` — 3DES is transform id 3
under the ISAKMP ESP numbering, and RFC 8221 marks it SHOULD NOT.

No language model can produce evidence at that standard, because evidence is
the opposite of what these models do. They produce a plausible string. A
finding must be a *fact with a location*.

`AGENTS.md` already encodes the rule: **ML handles uncertainty only, never a
deterministic field.** An algorithm id is the most deterministic field there is.
It is read off the wire. Putting a model in that path would be a regression, not
a feature.

## What the 14B is actually good for

It is a fine artefact for **RAKSHAK.AI**, the other project, where the input is
source code and the output is a review comment. It belongs on that slide, not
on this one.

Using it on a VYUH slide would also invite the question you cannot answer:
"14 billion parameters, for which of your six tunnels?" The answer would be
none, and "none" is a bad thing to say about your headline component.

## If you want ML anyway

The honest place for it, if time allows:

| Use | Feasible? | Why |
|-----|-----------|-----|
| Traffic classification (VPN vs non-VPN) | Yes | 1-D CNN on a 1500-packet window, ~2 MB model |
| Anomaly score on SA behaviour | Yes | IsolationForest, interpretable, small |
| **Algorithm identification** | **No** | Already exact. Never. |

Train on **ISCX-VPN** or your own six captures plus more, report held-out
macro-F1, and calibrate. Budget: 2 weeks. Only after the parser is airtight —
which it now is.

**My recommendation: skip it.** `vyuh --batch corpus` discriminates six real
tunnels across every grade in **0.1 seconds each**, with every number traceable
to a packet. That is a stronger demo than a model accuracy figure, and it is
true.

## The real risk in your current deck

Not "the model is too small." That is a fair question with a good answer.

The risk is that a judge asks **"how do you know ENCR 3DES is 3DES and not
DES?"** — and you need packet #1 open on screen to show `80 01 00 03`.

You had exactly that bug. The old registry read ISAKMP transform 3 as DES. It
was caught only because `tests/corpus.rs` checks against `tcpdump`, not because
a model approved it. **That test suite is the asset, not the model.** Lead with
it.
