# Experiment Log

Results are pending. Entries will be appended only after their corresponding runs complete.

## exp_002_sft_v1

- Date: 2026-09-18 (Asia/Seoul)
- Git commit used by the probes: `e335fef614bd9b7a0e85190cd27d2832db740e60`
- Status: blocked before the full run; all permitted probe configurations OOMed before completing one optimizer step.
- Base config: `configs/sft.yaml`; `training.max_steps: null` was added so the probe override is unused in a normal run.
- Hardware: NVIDIA GeForce RTX 2060 6 GiB, compute capability 7.5, driver 535.230.02, CUDA 12.1, PyTorch 2.5.1+cu121. At the initial check, 4,168 MiB was used and 1,757 MiB was free; protected PID 65998 (`llama-server`) held 4,160 MiB.
- Software relevant to QLoRA: bitsandbytes 0.50.2, Transformers 5.17.0, TRL 1.13.0, PEFT 0.21.0, Accelerate 1.15.0.
- Trainable parameters: 4,587,520 / 600,637,440 (0.7638%) in all three probes.
- Probe wall time: approximately 31 seconds per attempt including model load and dataset preprocessing; zero training steps completed, so training samples/s was unavailable.
- Full-run wall-time estimate: unavailable because no probe completed a training step.
- Final train loss: unavailable.
- Eval loss per epoch: unavailable.
- Full-run wall time and peak VRAM: unavailable; the full run was not launched.

### VRAM probe

| Attempt | Resolved deviations from `configs/sft.yaml` | Peak allocated VRAM | Outcome |
|---|---|---:|---|
| 1 — LoRA | `training.max_steps=5` | 1,582.5 MiB | OOM on the first forward pass while requesting 150 MiB; 35.88 MiB GPU memory was free. Mask check: 815 prompt/padding tokens masked, 27 completion tokens supervised. |
| 2 — LoRA | `training.max_steps=5`, batch size 1, gradient accumulation 16 | 1,582.5 MiB | OOM on the first forward pass while requesting 150 MiB; 11.88 MiB GPU memory was free. Mask check: 408 prompt/padding tokens masked, 13 completion tokens supervised. |
| 3 — QLoRA | `training.max_steps=5`, batch size 1, gradient accumulation 16, `quantization.load_in_4bit=true` | 1,479.8 MiB | bitsandbytes loaded the NF4 model and ran forward/backward on sm_75, then OOMed during backward recomputation while requesting 150 MiB; 133.88 MiB GPU memory was free. Mask check: 408 prompt/padding tokens masked, 13 completion tokens supervised. |

The fallback decision was QLoRA because both permitted fp16 LoRA configurations OOMed. QLoRA reduced the observed PyTorch peak by 102.7 MiB and verified that bitsandbytes works on this GPU, but it also OOMed. No further hyperparameter deviation was authorized, so no detached full training process was started. The final failed-probe overrides are preserved in `experiments/exp_002_sft_v1/config_resolved.yaml`; no adapter, `train_log.jsonl`, or `metadata.json` was produced.

## exp_002_sft_v1 — training

- Date: 2026-09-19 (Asia/Seoul)
- Model: `Qwen/Qwen3-0.6B` at revision `c1899de289a04d12100db370d81485cdf75e47ca`.
- Dataset: v1.1, 12,000 natural-distribution train rows and 1,000 validation rows; dataset hash `ab321617504329a0e00469637aa75a13a457d1c8cfa82db37002fb40ae83ad26`.
- Configuration: fp16 LoRA, rank 16, alpha 32, dropout 0.05, target modules `q_proj,k_proj,v_proj,o_proj`, sequence length 1,536, batch 2, gradient accumulation 8, effective batch 16, learning rate 0.0002, cosine schedule, three epochs.
- Trainable parameters: 4,587,520 / 600,637,440 (0.7638%).
- Completion-mask audit: `rows=12000 truncated_completions=0` in both smoke and full runs.
- Runtime: 7,835.1 seconds (2 h 10 m 35 s); peak allocated VRAM 2,001.4 MiB; 2,250 optimizer steps.
- Loss: first logged training window 0.201267; last logged training window 0.008126; aggregate train loss 0.022726.
- Validation loss: 0.022035 (epoch 1), 0.018494 (epoch 2), 0.018537 (epoch 3).
- Adapter: `experiments/exp_002_sft_v1/adapter/adapter_model.safetensors`; tokenizer and chat-template files are colocated in the adapter directory.
- Observed issues: none in Attempt 3. Earlier co-tenant OOM probes remain documented above and in `agent/T-003_EXEC.md`.

## exp_002_sft_v1 — evaluation

- Date: 2026-09-19 (Asia/Seoul).
- Frozen subset: 18,000 rows; subset hash `229dd47c3cdeb532d47c2dd8c5962f2c9bff8ff2c6d89d8d2776ee6d09a7d707`; ordered CVE sequence exactly equals the Base prediction sequence.
- Generation: greedy, 32 maximum new tokens, sequence budget 1,536, batch size 8; adapter merged for evaluation.
- Runtime: 2,025.4 seconds at 8.8871 samples/second; peak allocated VRAM 2,574.8 MiB.

| Metric | Base | SFT | Delta |
|---|---:|---:|---:|
| Accuracy | 0.396944 | 0.862667 | +0.465722 |
| Macro F1 | 0.304829 | 0.833186 | +0.528356 |
| Weighted F1 | 0.389095 | 0.863559 | +0.474463 |
| Invalid-output rate | 0.023667 | 0.000000 | -0.023667 |

- Transitions: 6,813 both right, 8,715 fixed by SFT, 332 broken by SFT, and 2,140 both wrong.
- Prediction concentration on the top three predicted classes changed from 0.7185 to 0.417167.
- Tracked access-control sinks changed from 1,976 to 138 for CWE-862→CWE-200 and from 1,573 to 138 for CWE-284→CWE-200.
- Tracked memory-related confusions changed from 724 to 1 for CWE-416→CWE-434, 619 to 133 for CWE-787→CWE-120, and 519 to 4 for CWE-125→CWE-120.
- Every class gained F1. Recall declined for CWE-200 by 0.300254 and CWE-120 by 0.224080; no other class had a recall decline.
- Accuracy co-occurred with gains in both token-length slices: `<480` 0.427907→0.865678 and `480-1536` 0.160346→0.839654. Description-length slice results are in `reports/comparison.md` and `reports/failure_summary.json`; these are co-occurrences, not causal claims.
- Manual review covered 30 residual failures: 15 broken-by-SFT rows followed by one both-wrong row from each class. Notes are in `agent/T-004_EXEC.md`.
