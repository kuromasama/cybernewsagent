---
layout: post
title:  "Trojanized Newtonsoft.Json Fork Hides Game-Rigging Code in a Working Library"
date:   2026-07-22 08:13:30 +0000
categories: [security]
severity: high
---

# 🔥 解析 NuGet Typosquat 攻擊：利用 Trojanized Newtonsoft.Json 來操控線上遊戲結果

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: RCE (Remote Code Execution) 和 Data Tampering
> * **關鍵技術**: Deserialization, Reflection, Obfuscation

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者透過創建一個名為 "Newtonsoftt.Json.Net" 的 NuGet 套件，該套件實際上是一個 Trojanized 的 Newtonsoft.Json 版本。這個套件會在 `JsonConvert.DefaultSettings` 被設定時啟動惡意行為，利用反射機制來修改遊戲結果。
* **攻擊流程圖解**:
  1. 使用者安裝 "Newtonsoftt.Json.Net" 套件。
  2. 套件被初始化，設定 `JsonConvert.DefaultSettings`。
  3. 惡意程式碼透過反射機制修改遊戲結果。
  4. 修改後的結果被傳送到攻擊者的伺服器。
* **受影響元件**: Newtonsoft.Json 13.0 版本，Digitain 線上遊戲平台。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有權限安裝 NuGet 套件，且目標系統需要使用 Newtonsoft.Json。
* **Payload 建構邏輯**:

    ```
    
    csharp
    // 範例 Payload
    using Newtonsoft.Json;
    using System.Reflection;
    
    public class MaliciousPayload
    {
        public static void Initialize()
        {
            // 使用反射機制修改遊戲結果
            typeof(JsonConvert).GetMethod("DefaultSettings").Invoke(null, new object[] { });
            // ...
        }
    }
    
    ```
* **繞過技術**: 攻擊者使用了混淆技術 (Obfuscation) 來隱藏惡意程式碼，同時也使用了反射機制來修改遊戲結果，避免被偵測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 185.126.237.64 |
| Domain | theperfectheist2025.com |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Malicious_NuGet_Package
    {
        meta:
            description = "Detects malicious NuGet package"
            author = "Your Name"
        strings:
            $s1 = "Newtonsoftt.Json.Net"
            $s2 = "JsonConvert.DefaultSettings"
        condition:
            $s1 and $s2
    }
    
    ```
* **緩解措施**: 移除 "Newtonsoftt.Json.Net" 套件，封鎖攻擊者的 IP 和 Domain，同時也需要更新 Newtonsoft.Json 到最新版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Deserialization**: 將資料從字串或其他格式轉換回物件的過程。這個過程可能會被攻擊者利用來執行惡意程式碼。
* **Reflection**: 一種程式設計技術，允許程式在執行時檢查和修改自己的結構和行為。這個技術可能會被攻擊者利用來修改遊戲結果。
* **Obfuscation**: 一種技術，用于隱藏程式碼的意圖和行為。這個技術可能會被攻擊者利用來隱藏惡意程式碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/trojanized-newtonsoftjson-fork-hides.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


