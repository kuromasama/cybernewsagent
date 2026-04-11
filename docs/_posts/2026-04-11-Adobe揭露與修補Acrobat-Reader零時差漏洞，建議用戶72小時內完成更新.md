---
layout: post
title:  "Adobe揭露與修補Acrobat Reader零時差漏洞，建議用戶72小時內完成更新"
date:   2026-04-11 18:34:54 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Acrobat Reader 零時差漏洞：CVE-2026-34621 原型汙染攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數: 9.6)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Prototype Pollution`, `Deserialization`, `Use-after-free`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞源於 Adobe Acrobat Reader 對物件原型屬性的修改管理不當，導致原型汙染（Prototype Pollution）。這種攻擊方式可以讓攻擊者修改 JavaScript 物件的原型，進而影響到其他物件的行為。
* **攻擊流程圖解**: 
    1. 攻擊者創建一個惡意的 PDF 文件，內含有特定的 JavaScript 代碼。
    2. 當用戶打開 PDF 文件時，Acrobat Reader 會執行 JavaScript 代碼。
    3. 代碼利用原型汙染漏洞修改 Acrobat Reader 的內部物件原型。
    4. 攻擊者可以利用修改後的原型執行任意代碼。
* **受影響元件**: Acrobat DC 與 Acrobat Reader DC 的版本早於 26.001.21367，Acrobat 2024 的版本早於 24.001.30356。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個惡意的 PDF 文件，並且用戶需要打開該文件。
* **Payload 建構邏輯**:

    ```
    
    javascript
        // 範例 Payload
        var obj = {};
        obj.__proto__ = {
            // 修改原型屬性
            toString: function() {
                // 執行任意代碼
                return "任意代碼";
            }
        };
    
    ```
    *範例指令*: 可以使用 `curl` 或 `python` 腳本來傳送惡意的 PDF 文件給用戶。
* **繞過技術**: 攻擊者可以使用各種技術來繞過防禦，例如使用壓縮或加密的 PDF 文件來避免被檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | XXXX | XXXX | XXXX |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
        rule Acrobat_Reader_Vulnerability {
            meta:
                description = "Acrobat Reader 原型汙染漏洞"
                author = "您的名字"
            strings:
                $a = "toString" ascii
                $b = "__proto__" ascii
            condition:
                all of them
        }
    
    ```
    或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)。
* **緩解措施**: 除了更新 Acrobat Reader 到最新版本之外，還可以設定防火牆或 IDS/IPS 來阻止惡意的 PDF 文件傳輸。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Prototype Pollution (原型汙染)**: 想像兩個物件共享同一個原型，如果其中一個物件修改了原型的屬性，另一個物件也會受到影響。技術上是指修改 JavaScript 物件的原型，進而影響到其他物件的行為。
* **Deserialization (反序列化)**: 將資料從序列化的格式（例如 JSON 或 XML）轉換回原始的物件或資料結構。
* **Use-after-free (用後釋放)**: 當一個物件被釋放後，仍然試圖存取該物件的內容，可能會導致數據不一致或邏輯錯誤。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174998)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1204/)


