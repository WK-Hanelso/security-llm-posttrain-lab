# Security-domain LLM Post-training & Evaluation

## One-line

NVD CVE를 canonical security record와 고정된 CWE 정책으로 구조화하고, temporal split·exact overlap guard·frozen evaluation을 통과시킨 뒤 Qwen3-0.6B LoRA SFT에서 Accuracy 0.3969→0.8627, Macro F1 0.3048→0.8332를 확인했다.

## Problem

공개 CVE 설명을 CWE로 분류하려면 원천 데이터 정규화, label 정책, 시간 분할, 누수 방지가 모델 학습과 함께 고정돼야 한다. Base 모델은 동일한 18,000개 평가 ID에서 Accuracy 0.3969였고, CWE-200·CWE-120 같은 generic class로 예측이 집중됐다. 생성형 출력은 허용 label 밖의 CWE를 내놓을 수도 있어 형식 및 label 검증도 필요했다. 따라서 데이터 구축부터 같은-test 평가와 실패 분석까지 하나의 검증 가능한 프로토콜로 묶었다.

## Decision

- label은 2020–2024 학습 구간에서 선정한 상위 15개 CWE의 single-label closed set으로 제한했다.
- NVD `published` 기준 temporal split을 사용하고, 정규화 설명의 exact hash 중복과 split overlap을 SFT build 전에 제거·차단했다.
- Base와 LoRA SFT에 같은 ordered 18,000-ID subset, prompt, greedy decoding, deterministic verifier를 적용했다.
- Accuracy만 보지 않고 Macro/Weighted F1, invalid output, row transition, 반복 confusion sink를 함께 비교했다.

## What I Built

- NVD API record를 typed canonical security record로 정규화·검증하는 data layer
- training-period label selection, temporal split, exact dedup, fail-fast overlap guard
- canonical record를 fixed CWE instruction과 JSON completion으로 바꾸는 model adapter
- Qwen3-0.6B completion-only LoRA SFT와 frozen same-test Base/SFT evaluation
- confusion, transition, long-tail slice를 남기는 deterministic failure-analysis report

## Evidence

- Accuracy: **0.3969 → 0.8627**
- Macro F1: **0.3048 → 0.8332**
- Weighted F1: **0.3891 → 0.8636**
- Invalid-output rate: **2.37% → 0%**
- Row transitions: **8,715 fixed by SFT / 332 broken by SFT**, total 18,000

모든 수치는 동일한 ordered 18,000-ID frozen subset에서 계산됐다. Base의 대표 sink인 CWE-862→CWE-200은 1,976→138, CWE-416→CWE-434는 724→1로 줄었다.

## Failure / Debugging

데이터 준비 중 SFT sampling 전 정규화 설명의 exact overlap이 train–validation 92건, train–test 7건 발견됐다. 학습 내부 중복을 제거하고 validation/test와 겹치는 train record를 제외한 뒤 fail-fast guard에서 post-build split overlap 0을 확인했다. 이 검사는 exact hash 범위이며 semantic contamination이나 Base 모델의 과거 데이터 노출을 증명하지 않는다.

초기 fp16 LoRA 두 구성과 4-bit fallback은 GPU co-tenant가 메모리를 점유한 상태에서 첫 optimizer step 전에 OOM이 발생했고, 별도 시도에서는 CUDA driver 초기화가 실패했다. GPU·driver 상태를 확인한 뒤 같은 fp16 LoRA 설정의 성공 실행이 3 epochs, 2,250 steps를 완료했다. 실패 로그와 성공 실행 기록을 함께 보존해 최종 상태를 과장하지 않았다.

## Result

LoRA SFT 이후 세 분류 지표가 모두 상승했고 허용 label 밖 출력 426건이 0건이 됐다. Base의 generic prediction sink가 크게 줄었으며, 잔여 최빈 confusion은 더 가까운 access-control 경계인 CWE-862→CWE-284 367건으로 나타났다. 이는 frozen protocol 안의 단일 실험 결과이며 다른 모델·snapshot으로의 일반화를 주장하지 않는다.

## Scope / Limitation

- Qwen3-0.6B 단일 모델, LoRA SFT만 평가했다.
- CPT와 RLVR은 수행하지 않았고 verifier는 RL reward가 아니다.
- 한 번의 temporal snapshot과 단일 seed(42) 결과다.
- top-15 single-label closed set만 다루며 multi-label CVE는 제외했다.
- exact normalized-description hash 검사는 paraphrase를 찾지 못하며, sampled near-duplicate audit도 정식 semantic-contamination detector가 아니다.
- Base 모델이 원래 학습에서 NVD text를 보았는지는 확인할 수 없다.

## Portfolio Assets

- [`assets/01_base_vs_sft_metrics.png`](assets/01_base_vs_sft_metrics.png): 같은 frozen test에서 Base와 SFT의 세 핵심 지표 및 invalid-output 변화를 보여준다.
- [`assets/02_confusion_reduction.png`](assets/02_confusion_reduction.png): Base가 반복하던 5개 semantic prediction sink의 감소를 보여준다.
- [`assets/03_security_data_pipeline.svg`](assets/03_security_data_pipeline.svg): NVD ingest부터 failure analysis까지 data/model layer의 책임과 guard를 보여준다.
- [`assets/04_transition_summary.png`](assets/04_transition_summary.png): 18,000개 row가 SFT 뒤 어떤 결과 상태로 이동했는지 보여준다.

실제 근거 위치는 [`EVIDENCE.md`](EVIDENCE.md), 이미지별 문구와 claim boundary는 [`CAPTIONS.md`](CAPTIONS.md)에 정리했다.
