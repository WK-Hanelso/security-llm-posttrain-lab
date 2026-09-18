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
