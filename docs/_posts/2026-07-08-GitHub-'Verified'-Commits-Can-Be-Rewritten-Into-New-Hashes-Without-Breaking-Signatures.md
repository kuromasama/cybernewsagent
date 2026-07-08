---
layout: post
title:  "GitHub 'Verified' Commits Can Be Rewritten Into New Hashes Without Breaking Signatures"
date:   2026-07-08 13:47:01 +0000
categories: [security]
severity: high
---

# 🔥 Git Commit Hash 繞過攻擊：解析與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Commit Hash 繞過，可能導致代碼驗證失敗
> * **關鍵技術**: Git Commit Hash、簽名驗證、ECDSA、RSA、S/MIME

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Git Commit Hash 的計算過程中，包含了簽名的原始位元組，這使得攻擊者可以通過修改簽名的格式來改變 Commit Hash，而不需要更改代碼內容。
* **攻擊流程圖解**:
  1. 攻擊者計算原始 Commit Hash
  2. 攻擊者修改簽名的格式（例如，ECDSA 的 s 值、RSA 的未雜湊部分、S/MIME 的 DER 結構）
  3. 攻擊者重新計算 Commit Hash
  4. 攻擊者提交新的 Commit，具有相同的代碼內容但不同的 Commit Hash
* **受影響元件**: GitHub、Git 版本控制系統

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有簽名金鑰和原始 Commit 的存取權
* **Payload 建構邏輯**:

    ```
    
    python
    import hashlib
    import ecdsa
    
    # 原始 Commit Hash
    original_hash = "..."
    
    # 修改簽名的格式
    def modify_signature(signature):
        # ECDSA 的 s 值修改
        s = signature[32:]
        new_s = hashlib.sha256(s).digest()
        return signature[:32] + new_s
    
    # 重新計算 Commit Hash
    new_hash = hashlib.sha256(modify_signature(original_hash)).hexdigest()
    
    # 提交新的 Commit
    print("新的 Commit Hash:", new_hash)
    
    ```
* **繞過技術**: 攻擊者可以使用這種方法繞過代碼驗證，提交具有相同代碼內容但不同的 Commit Hash 的 Commit

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule git_commit_hash_attack {
        meta:
            description = "Git Commit Hash 攻擊"
            author = "..."
        strings:
            $a = "git commit"
            $b = "sha256"
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 使用 canonicalize 的簽名驗證，例如使用 `git verify-commit` 命令進行驗證

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **ECDSA (Elliptic Curve Digital Signature Algorithm)**: 一種基於橢圓曲線的數字簽名算法，使用於 Git Commit 的簽名驗證。
* **RSA (Rivest-Shamir-Adleman)**: 一種基於大整數的公鑰加密算法，使用於 Git Commit 的簽名驗證。
* **S/MIME (Secure/Multipurpose Internet Mail Extensions)**: 一種基於 MIME 的安全電子郵件協議，使用於 Git Commit 的簽名驗證。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/github-verified-commits-can-be.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


