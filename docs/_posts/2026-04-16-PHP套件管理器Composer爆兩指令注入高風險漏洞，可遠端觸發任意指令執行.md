---
layout: post
title:  "PHP套件管理器Composer爆兩指令注入高風險漏洞，可遠端觸發任意指令執行"
date:   2026-04-16 02:02:34 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Composer 高嚴重性指令注入漏洞：CVE-2026-40261 與 CVE-2026-40176

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `指令注入`, `Shell 特殊字元`, `軟體供應鏈攻擊`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: Composer 的 Perforce 驅動程式在組合系統指令時，直接將外部提供的參數嵌入指令字串，未經過濾或跳脫處理，導致攻擊者可藉由在參數中夾帶 Shell 特殊字元來注入任意指令。
* **攻擊流程圖解**:
	1. 攻擊者創建一個惡意的 Composer 套件儲存庫。
	2. 攻擊者在套件中繼資料中宣告 Perforce 為來源類型，並夾帶惡意內容。
	3. 開發者從遭入侵或蓄意架設的 Composer 儲存庫安裝套件。
	4. Composer 執行 Perforce::syncCodeBase() 方法，將來源參照直接附加到 Shell 指令中。
	5. 攻擊者可藉由在參數中夾帶 Shell 特殊字元來注入任意指令。
* **受影響元件**: Composer 2.0 至 2.2.26 的 LTS 分支，以及 2.3 至 2.9.5 的主線分支。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要創建一個惡意的 Composer 套件儲存庫，並將其發佈到網路上。
* **Payload 建構邏輯**:

    ```
    
    json
    {
      "name": "malicious-package",
      "version": "1.0.0",
      "type": "perforce",
      "source": {
        "url": "https://example.com/malicious-repo",
        "reference": "master"
      }
    }
    
    ```
* **範例指令**: 攻擊者可以使用 `curl` 指令將惡意套件儲存庫發佈到網路上：

```

bash
curl -X POST \
  https://example.com/malicious-repo \
  -H 'Content-Type: application/json' \
  -d '{"name": "malicious-package", "version": "1.0.0", "type": "perforce", "source": {"url": "https://example.com/malicious-repo", "reference": "master"}}'

```
* **繞過技術**: 攻擊者可以使用 WAF 繞過技巧，例如使用 URL 編碼或 Base64 編碼來隱藏惡意內容。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /var/www/html/malicious-package |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_package {
      meta:
        description = "Detects malicious Composer package"
      strings:
        $a = "perforce"
        $b = "https://example.com/malicious-repo"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 開發者可以改用下載封裝檔的方式安裝套件，避免以原始碼方式取得相依套件。另外，開發者應避免在來源不明的專案目錄中執行 Composer 指令。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **指令注入 (Command Injection)**: 想像攻擊者可以在系統指令中插入任意指令，導致系統執行惡意動作。技術上是指攻擊者可以在系統指令中注入任意指令，導致系統執行惡意動作。
* **Shell 特殊字元 (Shell Special Characters)**: 想像 Shell 特殊字元可以用來分隔指令或檔案路徑，例如 `;`、`|`、`>` 等。技術上是指 Shell 特殊字元可以用來分隔指令或檔案路徑。
* **軟體供應鏈攻擊 (Software Supply Chain Attack)**: 想像攻擊者可以在軟體供應鏈中注入惡意軟體，導致使用者安裝惡意軟體。技術上是指攻擊者可以在軟體供應鏈中注入惡意軟體，導致使用者安裝惡意軟體。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://www.ithome.com.tw/news/175089)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


