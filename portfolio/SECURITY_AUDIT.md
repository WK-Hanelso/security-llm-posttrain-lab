# Confidentiality Audit

## Scope

검사 대상은 `portfolio/` 아래의 Markdown, JSON, SVG, PNG, 생성 스크립트 전체다. 공개 artifact에 사내 hostname, absolute internal path, IP address, vehicle identifier, private API endpoint, topic name, credential/secret/token, 개인정보가 남지 않았는지 확인했다.

## Checks

### Text and SVG/script scan

```bash
rg -n -i --glob '*.md' --glob '*.json' --glob '*.svg' --glob '*.py' \
  '(?:/(?:home|Users|srv|workspace)/)|(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:https?://)?[a-z0-9.-]+\.(?:internal|local|corp)\b|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|(token|secret|password|api[_-]?key)\s*[:=]\s*[^ ,;]+' portfolio
```

결과: private/internal 값 0건. 별도 `rg -n 'https?://' portfolio` URL inventory에서는 SVG 표준 namespace와 Matplotlib provenance의 공개 URL만 발견해 allowlist 처리했다.

### Sensitive identifier vocabulary scan

```bash
rg -n -i --glob '*.md' --glob '*.json' --glob '*.svg' --glob '*.py' \
  '\b(hostname|vehicle[_ -]?id|topic[_ -]?name|private api|production|enterprise|large-scale)\b' portfolio
```

결과: 실제 identifier 0건. 이 audit 문서 자체의 검사 항목명과 명령 정규식만 self-match했다.

### PNG embedded-string scan

```bash
for f in portfolio/assets/*.png; do strings "$f"; done | \
  rg -n -i '(?:/(?:home|Users)/)|(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:token|secret|password|api[_-]?key)|hostname|vehicle[_ -]?id|topic[_ -]?name'
```

결과: sensitive 값 0건. Matplotlib version과 공개 project URL metadata만 존재한다.

### Manual visual review

- 4개 PNG를 원본 해상도로 열어 path, hostname, IP, user identifier, secret 노출 여부를 확인했다.
- 그림에는 aggregate metric, public CWE identifier, public model/source 명칭만 있다.
- 개별 CVE record나 description excerpt는 portfolio asset에 포함하지 않았다.

## Actions

- Source 위치는 repo-relative path와 JSON key/line으로만 기록했다.
- 초기 실패 기록에서 host/PID와 같은 machine-specific identifier를 제외하고 일반화된 resource condition만 서술했다.
- pipeline 그림 안에는 코드 경로를 넣지 않고, 공개 문서인 `CAPTIONS.md`에 repo-relative module mapping을 분리했다.

## Result

**PASS** — 공개 제출물에서 private infrastructure, credential, 개인정보, 내부 absolute path가 발견되지 않았다.
