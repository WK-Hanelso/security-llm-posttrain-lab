# Notion-ready Captions

## 01_base_vs_sft_metrics.png

Notion 위치: Featured Work 첫 화면, One-line 바로 아래 hero image

Caption: 동일한 ordered 18,000-ID frozen evaluation subset에서 Qwen3-0.6B Base와 LoRA SFT를 비교했다. Accuracy 0.3969→0.8627, Macro F1 0.3048→0.8332, Weighted F1 0.3891→0.8636으로 상승했고 invalid-output rate는 2.37%→0%로 감소했다.

Claim boundary: 단일 모델·단일 seed·단일 temporal snapshot의 closed-set 평가다. 세 score와 invalid-output rate는 서로 다른 축으로 표시했으며 다른 모델이나 운영 환경으로 일반화하지 않는다.

## 01_base_vs_sft_metrics.svg

Notion 위치: PNG의 고해상도 대체본 또는 확대 가능한 원본

Caption: PNG와 동일한 frozen-artifact 기반 Base/SFT 비교를 vector 형식으로 제공한다.

Claim boundary: `01_base_vs_sft_metrics.png`와 동일하다.

## 02_confusion_reduction.png

Notion 위치: Evidence 섹션, primary result 바로 다음

Caption: SFT 개선은 출력 형식에 그치지 않았다. Base가 generic CWE로 반복 수렴하던 5개 tracked confusion에서 CWE-862→200은 1,976→138, CWE-284→200은 1,573→138, CWE-416→434는 724→1로 감소했다.

Claim boundary: 사전에 추적한 5개 true→pred pair의 count만 보여준다. 전체 오류가 사라졌거나 label taxonomy가 완전히 해결됐다는 뜻은 아니다.

## 02_confusion_reduction.svg

Notion 위치: PNG의 고해상도 대체본

Caption: 5개 tracked semantic prediction sink의 Base/SFT count를 vector 형식으로 비교한다.

Claim boundary: `02_confusion_reduction.png`와 동일하다.

## 03_security_data_pipeline.svg

Notion 위치: What I Built 섹션 첫 이미지

Caption: 공개 NVD CVE에서 canonical record, training-period CWE policy, temporal split, exact dedup과 fail-fast guard를 거쳐 model adapter, Base/LoRA SFT, frozen same-test evaluation, failure analysis로 이어지는 검증 가능한 흐름이다.

Claim boundary: 저장소에 구현된 data/model evaluation workflow를 요약한 그림이다. 배포, 운영 자동화, 실시간 추론을 의미하지 않는다.

단계별 실제 코드 대응:

| Diagram stage | Repository module | Responsibility |
|---|---|---|
| NVD CVE | `src/security_llm/data/ingest_nvd.py` | NVD API pagination과 raw cache |
| Canonical Security Record | `src/security_llm/data/normalize.py`, `src/security_llm/data/schema.py` | record 정규화, typed schema, validation |
| CWE Label Policy | `src/security_llm/data/split.py:select_labels` | training-period top-k label 선택 |
| Temporal Split | `src/security_llm/data/split.py:assign_split,create_splits` | `published` 기준 train/val/test 분할 |
| Exact Dedup | `src/security_llm/data/dedup.py`, `src/security_llm/data/build_sft.py` | normalized-text hash 중복 제거와 SFT view 생성 |
| Fail-fast Guard | `src/security_llm/data/guard.py` | split 간 exact ID/text-hash overlap 차단 |
| Model Adapter | `src/security_llm/adapters/cwe_instruction.py`, `src/security_llm/data/build_sft.py:to_sft_row` | fixed instruction, output schema, prompt/completion serialization |
| Base / LoRA SFT | `src/security_llm/train/sft.py`, `src/security_llm/eval/generate.py` | completion-only LoRA 학습과 Base/SFT generation |
| Frozen Same-test Eval | `src/security_llm/eval/generate.py`, `src/security_llm/eval/verifier.py`, `src/security_llm/eval/metrics.py` | frozen row selection, deterministic parsing, metrics |
| Failure Analysis | `src/security_llm/eval/failure_analysis.py` | transition, confusion, error-type 분석 |

## 03_security_data_pipeline.png

Notion 위치: SVG를 지원하지 않는 표면용 대체본

Caption: data layer와 model/evaluation layer를 분리해 leakage guard와 동일 평가 프로토콜의 위치를 보여준다.

Claim boundary: `03_security_data_pipeline.svg`와 동일하며, 단계별 코드 대응은 위 표를 따른다.

## 04_transition_summary.png

Notion 위치: Evidence 섹션, confusion reduction 다음

Caption: 같은 18,000개 row를 전후 비교하면 6,813개는 두 모델 모두 정답, 8,715개는 SFT가 수정, 332개는 SFT에서 오답으로 전환, 2,140개는 두 모델 모두 오답이었다.

Claim boundary: row-level correctness transition count이며 통계적 유의성, 원인, 다른 데이터에서의 재현성을 뜻하지 않는다. 네 구간의 합은 정확히 18,000이다.

## 04_transition_summary.svg

Notion 위치: PNG의 고해상도 대체본

Caption: Base→SFT row transition 네 구간을 vector 형식으로 보여준다.

Claim boundary: `04_transition_summary.png`와 동일하다.
