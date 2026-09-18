# Sampled train/test near-duplicate audit

This sampled audit checks for template reuse; it is not a formal semantic-contamination detector.

## Method

- Cosine similarity on L2-normalized word TF-IDF vectors fitted on the 12,000 train descriptions plus the 300 sampled test descriptions; ngram_range=(1, 2), sublinear_tf=True, min_df=2, stop_words=None (English stop words kept).
- High similarity is cosine similarity >= 0.80; very high similarity is >= 0.90.
- Character 5-gram Jaccard uses lowercased, whitespace-normalized descriptions and is reported only for the top 20 pairs.

## Summary

| Slice | n | p50 | p90 | p95 | max | >=0.80 | >=0.90 | >=0.80 same label | >=0.80 different label |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| all | 300 | 0.269362 | 0.703621 | 0.743811 | 1.000000 | 8 | 3 | 5 | 3 |
| fixed_by_sft | 200 | 0.291304 | 0.717078 | 0.763315 | 1.000000 | 8 | 3 | 5 | 3 |
| both_wrong | 100 | 0.247175 | 0.660712 | 0.717604 | 0.788447 | 0 | 0 | 0 | 0 |

Among the top 20 pairs, 9 have the same gold/train label and 11 have different labels. Among the 8 pairs at or above 0.80, 5 have the same label and 3 have different labels; the same-label count of 5 is the relevant claim-boundary quantity.

## Stratified allocation

### fixed_by_sft

| Gold label | Sampled |
|---|---:|
| CWE-120 | 1 |
| CWE-125 | 18 |
| CWE-20 | 13 |
| CWE-200 | 1 |
| CWE-22 | 11 |
| CWE-284 | 31 |
| CWE-352 | 1 |
| CWE-416 | 31 |
| CWE-434 | 5 |
| CWE-476 | 7 |
| CWE-78 | 18 |
| CWE-787 | 12 |
| CWE-79 | 16 |
| CWE-862 | 31 |
| CWE-89 | 4 |

### both_wrong

| Gold label | Sampled |
|---|---:|
| CWE-120 | 1 |
| CWE-125 | 4 |
| CWE-20 | 9 |
| CWE-200 | 1 |
| CWE-22 | 3 |
| CWE-284 | 23 |
| CWE-352 | 3 |
| CWE-416 | 3 |
| CWE-434 | 2 |
| CWE-476 | 3 |
| CWE-78 | 4 |
| CWE-787 | 9 |
| CWE-79 | 3 |
| CWE-862 | 31 |
| CWE-89 | 1 |

## Manual review of top 20 pairs

Each judgment below answers, in order, whether the pair is effectively a copy, whether its overlap is only vendor boilerplate, whether a weakness sentence is repeated verbatim, and whether it is ordinary semantic similarity.

### 1. CVE-2026-39612 / CVE-2024-43355

- Similarity: 1.000000; char5 Jaccard: 0.650943
- Labels: gold `CWE-862`; nearest train `CWE-862`; same label: `true`
- Transition: `fixed_by_sft`; Base: `CWE-200`; SFT: `CWE-862`
- Test excerpt: Missing Authorization vulnerability in kutethemes KuteShop kuteshop allows Exploiting Incorrectly Configured Access Control Security Levels.This issue affects KuteShop: from n/a through <= 4.2.9.
- Train excerpt: Missing Authorization vulnerability in BearDev JoomSport allows Exploiting Incorrectly Configured Access Control Security Levels.This issue affects JoomSport: from n/a through 5.3.0.
- Manual category: `exact_or_near_copy`
- Audit questions: Copy **yes**; vendor boilerplate only **no**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — the short records share the same authorization and affected-version template, with only vendor, product, and version slots changed.

### 2. CVE-2026-18295 / CVE-2024-5875

- Similarity: 0.920797; char5 Jaccard: 0.892989
- Labels: gold `CWE-787`; nearest train `CWE-787`; same label: `true`
- Transition: `fixed_by_sft`; Base: `CWE-120`; SFT: `CWE-787`
- Test excerpt: GStreamer MRF File Parsing Out-Of-Bounds Write Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of GStreamer. User interaction is required to exploit this vulnerability in that the target must visit a malicious page …
- Train excerpt: IrfanView SHP File Parsing Out-Of-Bounds Write Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of IrfanView. User interaction is required to exploit this vulnerability in that the target must visit a malicious page …
- Manual category: `exact_or_near_copy`
- Audit questions: Copy **yes**; vendor boilerplate only **no**; weakness sentence verbatim **yes**; ordinary semantic similarity **no** — three full sentences, including the out-of-bounds-write mechanism, recur verbatim while product, file type, and ZDI identifier change.

### 3. CVE-2026-47010 / CVE-2024-21147

- Similarity: 0.900706; char5 Jaccard: 0.749020
- Labels: gold `CWE-284`; nearest train `CWE-200`; same label: `false`
- Transition: `fixed_by_sft`; Base: `CWE-200`; SFT: `CWE-284`
- Test excerpt: Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: ImageIO). Supported versions that are affected are Oracle Java SE: 8u491, 8u491-perf, 11.0.31, 17.0.19, 21.0.11, 25.0.3, 26.0.1; Oracle GraalVM for JDK: 17.0.19 and 2…
- Train excerpt: Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u411, 8u411-perf, 11.0.23, 17.0.11, 21.0.3, 22.0.1; Oracle GraalVM for JDK: 17.0.11, 21.0.3, 22.0.…
- Manual category: `vendor_boilerplate_only`
- Audit questions: Copy **no**; vendor boilerplate only **yes**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — Oracle Java advisory framing and deployment notes repeat, but the components, impacts, scores, and labels differ.

### 4. CVE-2026-47978 / CVE-2023-47064

- Similarity: 0.879501; char5 Jaccard: 0.835227
- Labels: gold `CWE-79`; nearest train `CWE-79`; same label: `true`
- Transition: `fixed_by_sft`; Base: `CWE-352`; SFT: `CWE-79`
- Test excerpt: Adobe Experience Manager versions 6.5.24, LTS SP1, 2026.04 and earlier are affected by a stored Cross-Site Scripting (XSS) vulnerability that could be abused by a low-privileged attacker to inject malicious scripts into vulnerable form fields. Malicious JavaScript may be executed in a victim's brow…
- Train excerpt: Adobe Experience Manager versions 6.5.18 and earlier are affected by a stored Cross-Site Scripting (XSS) vulnerability that could be abused by a low-privileged attacker to inject malicious scripts into vulnerable form fields. Malicious JavaScript may be executed in a victim’s browser when they brow…
- Manual category: `exact_or_near_copy`
- Audit questions: Copy **yes**; vendor boilerplate only **no**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — the same product, stored-XSS mechanism, vulnerable fields, and browser-execution text recur, with versions, punctuation, and a scope note changed.

### 5. CVE-2026-19885 / CVE-2024-5875

- Similarity: 0.868888; char5 Jaccard: 0.834507
- Labels: gold `CWE-787`; nearest train `CWE-787`; same label: `true`
- Transition: `fixed_by_sft`; Base: `CWE-200`; SFT: `CWE-787`
- Test excerpt: OriginLab Origin Viewer OGWU File Parsing Out-Of-Bounds Write Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of OriginLab Origin Viewer. User interaction is required to exploit this vulnerability in that the target…
- Train excerpt: IrfanView SHP File Parsing Out-Of-Bounds Write Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of IrfanView. User interaction is required to exploit this vulnerability in that the target must visit a malicious page …
- Manual category: `exact_or_near_copy`
- Audit questions: Copy **yes**; vendor boilerplate only **no**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — the ZDI record is slot-filled around the same file-parsing out-of-bounds-write mechanism, although “buffer” changes to “data structure.”

### 6. CVE-2026-35311 / CVE-2024-21216

- Similarity: 0.849118; char5 Jaccard: 0.807377
- Labels: gold `CWE-284`; nearest train `CWE-862`; same label: `false`
- Transition: `fixed_by_sft`; Base: `CWE-120`; SFT: `CWE-284`
- Test excerpt: Vulnerability in the WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.4.0 and 14.1.2.0.0. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise WebLogic Server. Successful atta…
- Train excerpt: Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Serv…
- Manual category: `vendor_boilerplate_only`
- Audit questions: Copy **no**; vendor boilerplate only **yes**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — the Oracle/WebLogic shell is shared, but privilege level, protocol, version, CVSS, and CWE label differ and no weakness sentence is stated.

### 7. CVE-2026-39655 / CVE-2024-43355

- Similarity: 0.845034; char5 Jaccard: 0.626728
- Labels: gold `CWE-862`; nearest train `CWE-862`; same label: `true`
- Transition: `fixed_by_sft`; Base: `CWE-200`; SFT: `CWE-862`
- Test excerpt: Missing Authorization vulnerability in TeconceTheme Mayosis Core allows Exploiting Incorrectly Configured Access Control Security Levels. This issue affects Mayosis Core: from n/a through 5.4.7.
- Train excerpt: Missing Authorization vulnerability in BearDev JoomSport allows Exploiting Incorrectly Configured Access Control Security Levels.This issue affects JoomSport: from n/a through 5.3.0.
- Manual category: `exact_or_near_copy`
- Audit questions: Copy **yes**; vendor boilerplate only **no**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — the entire short authorization template is retained with vendor, product, and version substitutions, though no complete sentence is verbatim.

### 8. CVE-2026-60789 / CVE-2021-35611

- Similarity: 0.815286; char5 Jaccard: 0.628571
- Labels: gold `CWE-284`; nearest train `CWE-20`; same label: `false`
- Transition: `fixed_by_sft`; Base: `CWE-200`; SFT: `CWE-284`
- Test excerpt: Vulnerability in the Oracle Sales Offline product of Oracle E-Business Suite (component: Internal Operations). Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Sales Offline. Su…
- Train excerpt: Vulnerability in the Oracle Sales Offline product of Oracle E-Business Suite (component: Offline Template). Supported versions that are affected are 12.1.1-12.1.3 and 12.2.3-12.2.10. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Sa…
- Manual category: `vendor_boilerplate_only`
- Audit questions: Copy **no**; vendor boilerplate only **yes**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — the same Oracle product framing and access sentence recur, but one impact is takeover and the other is partial denial of service with different labels.

### 9. CVE-2026-25258 / CVE-2024-38401

- Similarity: 0.788447; char5 Jaccard: 0.487500
- Labels: gold `CWE-125`; nearest train `CWE-416`; same label: `false`
- Transition: `both_wrong`; Base: `CWE-120`; SFT: `CWE-416`
- Test excerpt: Memory corruption while processing IOCTL calls for escape operations.
- Train excerpt: Memory corruption while processing concurrent IOCTL calls.
- Manual category: `weakness_phrase_repeated`
- Audit questions: Copy **no**; vendor boilerplate only **no**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — only the stock phrase “Memory corruption while processing … IOCTL calls” repeats; the operation modifiers differ and the records carry different labels.

### 10. CVE-2026-39592 / CVE-2024-43355

- Similarity: 0.779225; char5 Jaccard: 0.583333
- Labels: gold `CWE-862`; nearest train `CWE-862`; same label: `true`
- Transition: `fixed_by_sft`; Base: `CWE-200`; SFT: `CWE-862`
- Test excerpt: Missing Authorization vulnerability in Andy Ha DEPART depart-deposit-and-part-payment-for-woo allows Exploiting Incorrectly Configured Access Control Security Levels.This issue affects DEPART: from n/a through <= 1.0.7.
- Train excerpt: Missing Authorization vulnerability in BearDev JoomSport allows Exploiting Incorrectly Configured Access Control Security Levels.This issue affects JoomSport: from n/a through 5.3.0.
- Manual category: `exact_or_near_copy`
- Audit questions: Copy **yes**; vendor boilerplate only **no**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — the short authorization and affected-version template is the same apart from vendor, product, and version fields.

### 11. CVE-2026-60739 / CVE-2020-14582

- Similarity: 0.779154; char5 Jaccard: 0.604620
- Labels: gold `CWE-284`; nearest train `CWE-79`; same label: `false`
- Transition: `fixed_by_sft`; Base: `CWE-200`; SFT: `CWE-284`
- Test excerpt: Vulnerability in the Oracle Field Service product of Oracle E-Business Suite (component: Internal Operations). Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Field Service. Su…
- Train excerpt: Vulnerability in the Oracle iStore product of Oracle E-Business Suite (component: User Registration). Supported versions that are affected are 12.1.1-12.1.3 and 12.2.3-12.2.9. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle iStore. …
- Manual category: `vendor_boilerplate_only`
- Audit questions: Copy **no**; vendor boilerplate only **yes**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — Oracle advisory language and confidentiality/integrity impact phrasing dominate, while products, authentication, scope, and labels differ.

### 12. CVE-2026-47915 / CVE-2022-35665

- Similarity: 0.762482; char5 Jaccard: 0.730303
- Labels: gold `CWE-416`; nearest train `CWE-416`; same label: `true`
- Transition: `fixed_by_sft`; Base: `CWE-120`; SFT: `CWE-416`
- Test excerpt: Acrobat Reader versions 24.001.30365, 26.001.21651 and earlier are affected by a Use After Free vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
- Train excerpt: Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and earlier) are affected by a Use After Free vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction i…
- Manual category: `exact_or_near_copy`
- Audit questions: Copy **yes**; vendor boilerplate only **no**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — the same Acrobat Reader use-after-free, code-execution impact, and interaction requirement recur, with only version wording and the Adobe prefix changed.

### 13. CVE-2026-60761 / CVE-2020-2741

- Similarity: 0.760262; char5 Jaccard: 0.629149
- Labels: gold `CWE-284`; nearest train `CWE-125`; same label: `false`
- Transition: `both_wrong`; Base: `CWE-200`; SFT: `CWE-200`
- Test excerpt: Vulnerability in the Oracle Applications DBA product of Oracle E-Business Suite (component: Internal Operations). Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Oracle Applications DBA e…
- Train excerpt: Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions that are affected are Prior to 5.2.40, prior to 6.0.20 and prior to 6.1.6. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle …
- Manual category: `vendor_boilerplate_only`
- Audit questions: Copy **no**; vendor boilerplate only **yes**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — the Oracle disclosure shell and confidentiality impact recur, but products, privilege levels, versions, and CWE labels differ.

### 14. CVE-2026-0137 / CVE-2023-35693

- Similarity: 0.757513; char5 Jaccard: 0.595745
- Labels: gold `CWE-416`; nearest train `CWE-416`; same label: `true`
- Transition: `fixed_by_sft`; Base: `CWE-434`; SFT: `CWE-416`
- Test excerpt: In edgetpu_sync_fence_group_shutdown() of edgetpu-dmabuf.c, there is a possible elevation of privilege due to a use after free. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.
- Train excerpt: In incfs_kill_sb of fs/incfs/vfs.c, there is a possible memory corruption due to a use after free. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.
- Manual category: `weakness_phrase_repeated`
- Audit questions: Copy **no**; vendor boilerplate only **no**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — both Android-style records repeat “due to a use after free” and the two impact sentences, while the affected function and primary flaw wording differ.

### 15. CVE-2026-35287 / CVE-2024-21246

- Similarity: 0.754185; char5 Jaccard: 0.683398
- Labels: gold `CWE-284`; nearest train `CWE-862`; same label: `false`
- Transition: `both_wrong`; Base: `CWE-200`; SFT: `CWE-200`
- Test excerpt: Vulnerability in Oracle Application Testing Suite. The supported version that is affected is 13.3.0.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via TCP to compromise Oracle Application Testing Suite. Successful attacks of this vulnerability can result in …
- Train excerpt: Vulnerability in the Oracle Service Bus product of Oracle Fusion Middleware (component: OSB Core Functionality). The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Service Bus. Succ…
- Manual category: `vendor_boilerplate_only`
- Audit questions: Copy **no**; vendor boilerplate only **yes**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — Oracle framing, confidentiality impact, score, and vector repeat, but product, protocol, version, and labels differ without an explicit weakness sentence.

### 16. CVE-2026-61068 / CVE-2024-21154

- Similarity: 0.743265; char5 Jaccard: 0.589416
- Labels: gold `CWE-284`; nearest train `CWE-79`; same label: `false`
- Transition: `fixed_by_sft`; Base: `CWE-120`; SFT: `CWE-284`
- Test excerpt: Vulnerability in the PeopleSoft Enterprise FIN Billing Argentina product of Oracle PeopleSoft (component: Billing). The supported version that is affected is 9.1. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise PeopleSoft Enterprise FIN Bi…
- Train excerpt: Vulnerability in the PeopleSoft Enterprise HCM Human Resources product of Oracle PeopleSoft (component: Human Resources). The supported version that is affected is 9.2. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise PeopleSoft Enterprise H…
- Manual category: `vendor_boilerplate_only`
- Audit questions: Copy **no**; vendor boilerplate only **yes**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — the PeopleSoft/Oracle advisory structure is shared, while products, privileges, impacts, scores, and labels differ.

### 17. CVE-2026-83128 / CVE-2021-35611

- Similarity: 0.741656; char5 Jaccard: 0.566667
- Labels: gold `CWE-284`; nearest train `CWE-20`; same label: `false`
- Transition: `fixed_by_sft`; Base: `CWE-200`; SFT: `CWE-284`
- Test excerpt: Vulnerability in the Oracle Sales Offline product of Oracle E-Business Suite (component: Internal Operations). Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Sales Offline. S…
- Train excerpt: Vulnerability in the Oracle Sales Offline product of Oracle E-Business Suite (component: Offline Template). Supported versions that are affected are 12.1.1-12.1.3 and 12.2.3-12.2.10. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Sa…
- Manual category: `vendor_boilerplate_only`
- Audit questions: Copy **no**; vendor boilerplate only **yes**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — both describe Oracle Sales Offline in the same vendor format, but component, authentication, impact, score, and label differ.

### 18. CVE-2026-35327 / CVE-2020-14582

- Similarity: 0.738328; char5 Jaccard: 0.677215
- Labels: gold `CWE-284`; nearest train `CWE-79`; same label: `false`
- Transition: `fixed_by_sft`; Base: `CWE-200`; SFT: `CWE-284`
- Test excerpt: Vulnerability in the Oracle WebCenter Content product of Oracle Fusion Middleware (component: Content Server). Supported versions that are affected are 12.2.1.4.0 and 14.1.2.0.0. Easily exploitable vulnerability allows low privileged attacker with network access via HTTPS to compromise Oracle WebCe…
- Train excerpt: Vulnerability in the Oracle iStore product of Oracle E-Business Suite (component: User Registration). Supported versions that are affected are 12.1.1-12.1.3 and 12.2.3-12.2.9. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle iStore. …
- Manual category: `vendor_boilerplate_only`
- Audit questions: Copy **no**; vendor boilerplate only **yes**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — repeated Oracle scope and confidentiality/integrity language accounts for the overlap, while products, access conditions, versions, and labels differ.

### 19. CVE-2026-61280 / CVE-2021-35611

- Similarity: 0.735709; char5 Jaccard: 0.610606
- Labels: gold `CWE-284`; nearest train `CWE-20`; same label: `false`
- Transition: `fixed_by_sft`; Base: `CWE-200`; SFT: `CWE-284`
- Test excerpt: Vulnerability in the Oracle Sales for Handhelds product of Oracle E-Business Suite (component: Outlook Sync Win 32). Supported versions that are affected are 12.2.3-12.2.15. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Sales for H…
- Train excerpt: Vulnerability in the Oracle Sales Offline product of Oracle E-Business Suite (component: Offline Template). Supported versions that are affected are 12.1.1-12.1.3 and 12.2.3-12.2.10. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Sa…
- Manual category: `vendor_boilerplate_only`
- Audit questions: Copy **no**; vendor boilerplate only **yes**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — the Oracle E-Business advisory shell recurs, but product, component, impact mix, score, vector, and label differ.

### 20. CVE-2026-35307 / CVE-2024-21071

- Similarity: 0.730568; char5 Jaccard: 0.642520
- Labels: gold `CWE-284`; nearest train `CWE-284`; same label: `true`
- Transition: `both_wrong`; Base: `CWE-200`; SFT: `CWE-20`
- Test excerpt: Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0 and 15.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle…
- Train excerpt: Vulnerability in the Oracle Workflow product of Oracle E-Business Suite (component: Admin Screens and Grants UI). Supported versions that are affected are 12.2.3-12.2.13. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle Workflow. Whi…
- Manual category: `vendor_boilerplate_only`
- Audit questions: Copy **no**; vendor boilerplate only **yes**; weakness sentence verbatim **no**; ordinary semantic similarity **no** — the Oracle takeover and scope-change template recurs, while products, privilege levels, versions, scores, and vectors differ.

## Manual category counts

| Category | Top-20 count |
|---|---:|
| `exact_or_near_copy` | 7 |
| `vendor_boilerplate_only` | 11 |
| `weakness_phrase_repeated` | 2 |
| `normal_semantic_similarity` | 0 |
