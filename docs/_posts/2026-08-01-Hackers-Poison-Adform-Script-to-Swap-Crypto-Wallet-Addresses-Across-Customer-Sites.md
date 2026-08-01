---
layout: post
title:  "Hackers Poison Adform Script to Swap Crypto Wallet Addresses Across Customer Sites"
date:   2026-08-01 13:02:23 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Adform 廣告技術公司的 JavaScript 檔案篡改事件
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和資訊竊取
> * **關鍵技術**: JavaScript 篡改、供應鏈攻擊、XOR 加密

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Adform 的 `trackpoint-async.js` 檔案被攻擊者篡改，導致用戶的加密貨幣錢包地址被替換。
* **攻擊流程圖解**:
  1. 攻擊者篡改 `trackpoint-async.js` 檔案。
  2. 用戶訪問包含篡改檔案的網頁。
  3. 篡改檔案執行，替換用戶的加密貨幣錢包地址。
* **受影響元件**: Adform 的 `trackpoint-async.js` 檔案，版本號未知。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 Adform 的 `trackpoint-async.js` 檔案的寫入權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 篡改檔案的代碼結構
    var replacementString = "篡改後的地址";
    var xorKey = "六個字元的XOR金鑰";
    
    // 使用XOR加密替換字符串
    function encryptString(str) {
      var encryptedStr = "";
      for (var i = 0; i < str.length; i++) {
        encryptedStr += String.fromCharCode(str.charCodeAt(i) ^ xorKey.charCodeAt(i % xorKey.length));
      }
      return encryptedStr;
    }
    
    // 替換用戶的加密貨幣錢包地址
    function replaceAddress() {
      var address = document.getElementById("address").value;
      var encryptedAddress = encryptString(replacementString);
      document.getElementById("address").value = encryptedAddress;
    }
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全防護，例如使用加密或編碼來隱藏惡意代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 84.32.102.230 |
| Domain | s2.adform.net |
| File Path | trackpoint-async.js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Adform_Malicious_JS {
      meta:
        description = "Adform 的 trackpoint-async.js 檔案篡改"
      strings:
        $s1 = "篡改後的地址"
        $s2 = "六個字元的XOR金鑰"
      condition:
        $s1 and $s2
    }
    
    ```
* **緩解措施**: 更新 `trackpoint-async.js` 檔案，使用安全的加密方法保護用戶的加密貨幣錢包地址。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **供應鏈攻擊 (Supply Chain Attack)**: 想像一個公司的供應鏈就像一條長長的鏈子，如果鏈子上的一個環被攻擊者破壞，整個鏈子就會受到影響。技術上是指攻擊者針對公司的供應鏈中的某個環節進行攻擊，例如攻擊公司的第三方供應商或合作伙伴。
* **XOR 加密 (XOR Encryption)**: 一種簡單的加密方法，使用 XOR 運算符來加密數據。技術上是指使用一個金鑰來加密數據，金鑰的長度可以是任意的。
* **JavaScript 篡改 (JavaScript Tampering)**: 想像一個網頁的 JavaScript 代碼就像一塊磚，如果攻擊者可以篡改這塊磚，整個網頁就會受到影響。技術上是指攻擊者篡改網頁的 JavaScript 代碼，例如替換用戶的加密貨幣錢包地址。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/hackers-poison-adform-script-to-swap.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


