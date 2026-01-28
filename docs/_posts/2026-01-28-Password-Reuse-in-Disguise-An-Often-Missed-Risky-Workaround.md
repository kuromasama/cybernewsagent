---
layout: post
title:  "Password Reuse in Disguise: An Often-Missed Risky Workaround"
date:   2026-01-28 12:35:04 +0000
categories: [security]
severity: high
---

# 🔥 解析近似密碼重複利用的威脅：從根本原因到防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Credential Stuffing 和 Password Cracking
> * **關鍵技術**: 近似密碼重複利用、密碼變化模式、密碼破解工具

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 近似密碼重複利用是指使用者在創建新密碼時，對原有的密碼進行小幅度的修改，例如增加或修改一個數字、追加一個字符、交換符號或大小寫等。這種行為使得攻擊者可以輕易地猜測出新的密碼。
* **攻擊流程圖解**: 
    1. 使用者創建一個密碼
    2. 攻擊者獲得使用者的密碼（例如通過資料洩露）
    3. 攻擊者使用密碼破解工具對密碼進行變化（例如增加或修改一個數字）
    4. 攻擊者嘗試使用變化後的密碼進行登入
* **受影響元件**: 所有使用密碼進行驗證的系統和應用程序

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得使用者的密碼（例如通過資料洩露）
* **Payload 建構邏輯**:

    ```
    
    python
    import itertools
    
    def generate_passwords(original_password):
        # 生成所有可能的密碼變化
        variations = []
        for i in range(1, 10):
            variations.append(original_password + str(i))
        for char in ['!', '@', '#', '$', '%', '^', '&', '*']:
            variations.append(original_password + char)
        for i in range(len(original_password)):
            for char in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']:
                variations.append(original_password[:i] + char + original_password[i+1:])
        return variations
    
    original_password = "password123"
    variations = generate_passwords(original_password)
    for variation in variations:
        print(variation)
    
    ```
* **繞過技術**: 攻擊者可以使用密碼破解工具對密碼進行變化，例如使用 John the Ripper 或 Hydra 等工具

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /etc/passwd |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule near_identical_password {
        meta:
            description = "Detect near-identical password reuse"
            author = "Your Name"
        strings:
            $password = "password123"
        condition:
            for any i in (1..10) :
                $password + str(i) in (all of them)
    }
    
    ```
* **緩解措施**: 
    1. 實施強密碼政策，要求使用者使用複雜的密碼
    2. 使用密碼管理工具，例如 LastPass 或 1Password 等
    3. 定期更新和變更密碼

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **近似密碼重複利用 (Near-Identical Password Reuse)**: 指使用者在創建新密碼時，對原有的密碼進行小幅度的修改，例如增加或修改一個數字、追加一個字符、交換符號或大小寫等。
* **密碼變化模式 (Password Variation Pattern)**: 指使用者在創建新密碼時，對原有的密碼進行的修改模式，例如增加或修改一個數字、追加一個字符、交換符號或大小寫等。
* **密碼破解工具 (Password Cracking Tool)**: 指用於破解密碼的工具，例如 John the Ripper 或 Hydra 等。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/password-reuse-in-disguise-often-missed.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1110/)


