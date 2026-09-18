# Comparative Failure Analysis

All counts use the identical ordered 18,000-row Base/SFT evaluation subset.

## Outcome transitions

| Transition | Count |
|---|---:|
| `both_right` | 6,813 |
| `fixed_by_sft` | 8,715 |
| `broken_by_sft` | 332 |
| `both_wrong` | 2,140 |

## Error-type counts

| Outcome or error type | Base | SFT | Delta |
|---|---:|---:|---:|
| `correct` | 7,145 | 15,528 | +8,383 |
| `invalid_format` | 0 | 0 | +0 |
| `unknown_cwe` | 426 | 0 | -426 |
| `nearby_cwe_confusion` | 1,828 | 852 | -976 |
| `semantic_confusion` | 8,601 | 1,620 | -6,981 |

## Per-class F1 delta

Tail is the bottom third of labels by training-period count in `data/processed/labels.json`.

| CWE | Tier | Train count | Test support | Base F1 | SFT F1 | Delta |
|---|---|---:|---:|---:|---:|---:|
| CWE-79 | head | 19,261 | 3,771 | 0.8788 | 0.9629 | +0.0842 |
| CWE-862 | head | 3,354 | 2,161 | 0.1153 | 0.7781 | +0.6628 |
| CWE-284 | tail | 1,456 | 1,863 | 0.0117 | 0.7353 | +0.7236 |
| CWE-89 | head | 7,294 | 1,522 | 0.8450 | 0.9789 | +0.1339 |
| CWE-416 | head | 3,215 | 1,419 | 0.0028 | 0.9670 | +0.9642 |
| CWE-22 | head | 2,984 | 1,368 | 0.7437 | 0.9302 | +0.1865 |
| CWE-125 | head | 3,811 | 914 | 0.0317 | 0.9071 | +0.8754 |
| CWE-78 | head | 2,554 | 879 | 0.0462 | 0.9243 | +0.8782 |
| CWE-20 | head | 2,707 | 788 | 0.0176 | 0.6329 | +0.6154 |
| CWE-200 | tail | 1,921 | 786 | 0.1819 | 0.6420 | +0.4601 |
| CWE-787 | head | 6,304 | 749 | 0.0473 | 0.7665 | +0.7192 |
| CWE-476 | tail | 2,191 | 587 | 0.5282 | 0.9073 | +0.3792 |
| CWE-352 | head | 4,010 | 550 | 0.7918 | 0.9209 | +0.1291 |
| CWE-434 | tail | 2,061 | 344 | 0.1166 | 0.8189 | +0.7023 |
| CWE-120 | tail | 2,149 | 299 | 0.2139 | 0.6252 | +0.4113 |

## Top 10 confusions — Base

| Rank | Gold | Prediction | Count |
|---:|---|---|---:|
| 1 | CWE-862 | CWE-200 | 1,976 |
| 2 | CWE-284 | CWE-200 | 1,573 |
| 3 | CWE-416 | CWE-434 | 724 |
| 4 | CWE-20 | CWE-200 | 678 |
| 5 | CWE-787 | CWE-120 | 619 |
| 6 | CWE-79 | CWE-200 | 596 |
| 7 | CWE-125 | CWE-120 | 519 |
| 8 | CWE-22 | CWE-200 | 462 |
| 9 | CWE-125 | CWE-200 | 371 |
| 10 | CWE-416 | CWE-444 | 297 |

## Top 10 confusions — SFT

| Rank | Gold | Prediction | Count |
|---:|---|---|---:|
| 1 | CWE-862 | CWE-284 | 367 |
| 2 | CWE-284 | CWE-200 | 138 |
| 3 | CWE-862 | CWE-200 | 138 |
| 4 | CWE-284 | CWE-20 | 133 |
| 5 | CWE-787 | CWE-120 | 133 |
| 6 | CWE-284 | CWE-862 | 106 |
| 7 | CWE-200 | CWE-284 | 91 |
| 8 | CWE-20 | CWE-79 | 79 |
| 9 | CWE-862 | CWE-20 | 75 |
| 10 | CWE-200 | CWE-862 | 64 |

## Long-tail slice

| Records | Base accuracy | SFT accuracy | Delta |
|---:|---:|---:|---:|
| 3,879 | 0.3400 | 0.7515 | +0.4114 |

## Quoted failure records

The four broken-by-SFT records and six both-wrong records below have different gold classes. Excerpts are capped at 300 characters.

### 1. CVE-2018-25276

- Transition: `broken_by_sft`
- Gold: `CWE-120`
- Base: `CWE-120`
- SFT: `CWE-20`
- Error type: `semantic_confusion`

> RoboImport 1.2.0.72 contains a denial of service vulnerability that allows local attackers to crash the application by submitting oversized input to registration fields. Attackers can paste a 6000-byte buffer into the Registration Name and Registration Key fields and click Register to trigger an ap…

### 2. CVE-2018-25330

- Transition: `broken_by_sft`
- Gold: `CWE-89`
- Base: `CWE-89`
- SFT: `CWE-79`
- Error type: `nearby_cwe_confusion`

> Joomla! extension EkRishta 2.10 contains persistent cross-site scripting and SQL injection vulnerabilities that allow attackers to inject malicious code through profile fields and POST parameters. Attackers can inject script payloads in profile information fields like Address that execute when user…

### 3. CVE-2025-14726

- Transition: `broken_by_sft`
- Gold: `CWE-200`
- Base: `CWE-200`
- SFT: `CWE-862`
- Error type: `semantic_confusion`

> The Widgets for Social Photo Feed plugin for WordPress is vulnerable to unauthorized access of data and modification of data due to a missing capability check on the '/trustindex_feed_hook_instagram/troubleshooting' and '/trustindex_feed_hook_instagram/submit-data' REST API endpoints in all version…

### 4. CVE-2025-70072

- Transition: `broken_by_sft`
- Gold: `CWE-125`
- Base: `CWE-125`
- SFT: `CWE-20`
- Error type: `semantic_confusion`

> An issue in Assimp v.6.0.2 allows a remote attacker to cause a denial of service via the FBXConverter.cpp, FBXConverter::ConvertMeshMultiMaterial() components

### 5. CVE-2013-20005

- Transition: `both_wrong`
- Gold: `CWE-79`
- Base: `CWE-352`
- SFT: `CWE-352`
- Error type: `semantic_confusion`

> Qool CMS 2.0 RC2 contains a cross-site request forgery vulnerability that allows attackers to perform administrative actions by tricking logged-in users into visiting malicious web pages. Attackers can forge POST requests to the /admin/adduser endpoint with parameters like username, password, email…

### 6. CVE-2016-20034

- Transition: `both_wrong`
- Gold: `CWE-352`
- Base: `CWE-120`
- SFT: `CWE-862`
- Error type: `semantic_confusion`

> Wowza Streaming Engine 4.5.0 contains a privilege escalation vulnerability that allows authenticated read-only users to elevate privileges to administrator by manipulating POST parameters. Attackers can send POST requests to the user edit endpoint with accessLevel set to 'admin' and advUser paramet…

### 7. CVE-2016-20040

- Transition: `both_wrong`
- Gold: `CWE-22`
- Base: `CWE-120`
- SFT: `CWE-120`
- Error type: `semantic_confusion`

> TiEmu 3.03-nogdb+dfsg-3 contains a buffer overflow vulnerability in the ROM parameter handling that allows local attackers to crash the application or execute arbitrary code. Attackers can supply an oversized ROM parameter to the tiemu command-line interface to overflow the stack buffer and overwri…

### 8. CVE-2016-20044

- Transition: `both_wrong`
- Gold: `CWE-787`
- Base: `CWE-120`
- SFT: `CWE-120`
- Error type: `nearby_cwe_confusion`

> PInfo 0.6.9-5.1 contains a local buffer overflow vulnerability that allows local attackers to execute arbitrary code by supplying an oversized argument to the -m parameter. Attackers can craft a malicious input string with 564 bytes of padding followed by a return address to overwrite the instructi…

### 9. CVE-2018-25168

- Transition: `both_wrong`
- Gold: `CWE-434`
- Base: `CWE-352`
- SFT: `CWE-352`
- Error type: `semantic_confusion`

> Precurio Intranet Portal 2.0 contains a cross-site request forgery vulnerability that allows unauthenticated attackers to create administrative user accounts by submitting crafted POST requests. Attackers can forge requests to the /public/admin/user/submitnew endpoint with user creation parameters…

### 10. CVE-2019-25351

- Transition: `both_wrong`
- Gold: `CWE-862`
- Base: `CWE-200`
- SFT: `CWE-22`
- Error type: `semantic_confusion`

> Centova Cast 3.2.11 contains a file download vulnerability that allows authenticated attackers to retrieve arbitrary system files through the server.copyfile API endpoint. Attackers can exploit the vulnerability by supplying crafted parameters to download sensitive files like /etc/passwd using curl…

## What SFT fixed and what remains

- SFT fixed 8,715 Base errors and broke 332 Base-correct rows; 2,140 rows remained wrong.
- Unknown-CWE outputs changed from 426 to 0; nearby-CWE confusions changed from 1,828 to 852; semantic confusions changed from 8,601 to 1,620.
- Every class gained F1. The three largest gains were CWE-416 (+0.9642), CWE-78 (+0.8782), and CWE-125 (+0.8754).
- Long-tail accuracy changed from 0.3400 to 0.7515; 964 residual SFT failures have a long-tail gold label.
- The largest remaining confusion is CWE-862→CWE-284 (367). Recall decreased for CWE-200 (-0.3003) and CWE-120 (-0.2241).
- Top-three prediction concentration changed from 0.7185 to 0.4172.
- Lower accuracy was observed together with longer descriptions in the Base buckets; this is a co-occurrence, not a causal result.
