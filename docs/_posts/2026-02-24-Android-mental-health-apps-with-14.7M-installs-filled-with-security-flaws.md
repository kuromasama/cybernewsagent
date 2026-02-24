---
layout: post
title:  "Android mental health apps with 14.7M installs filled with security flaws"
date:   2026-02-24 01:26:15 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Android 心理健康應用程式的安全漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium / High (CVSS 分數：6.5-8.5)
> * **受駭指標**: Info Leak, RCE
> * **關鍵技術**: `Intent.parseUri()`, `java.util.Random`, `Heap Spraying`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Android 心理健康應用程式中的安全漏洞主要是由於開發人員沒有正確地驗證用戶輸入的 URI，導致攻擊者可以利用 `Intent.parseUri()` 方法來執行任意的 Intent。
* **攻擊流程圖解**:
  1. 攻擊者發送一個惡意的 URI 給應用程式。
  2. 應用程式使用 `Intent.parseUri()` 方法來解析 URI。
  3. 攻擊者可以利用這個方法來執行任意的 Intent，例如：獲取用戶的療程記錄。
* **受影響元件**: Android 10 及以下版本的應用程式，尤其是那些使用 `Intent.parseUri()` 方法的應用程式。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道應用程式的套件名稱和版本號。
* **Payload 建構邏輯**:

    ```
    
    java
      Intent intent = new Intent();
      intent.setComponent(new ComponentName("com.example.app", "com.example.app.Activity"));
      intent.setData(Uri.parse("https://example.com/malicious"));
      startActivity(intent);
    
    ```
 

```

python
  import requests

  # 發送惡意的 URI 給應用程式
  url = "https://example.com/malicious"
  response = requests.get(url)

```
* **繞過技術**: 攻擊者可以利用 `java.util.Random` 類別來生成隨機的數據，從而繞過一些安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /data/data/com.example.app/files |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Android_Malicious_Intent {
        meta:
          description = "Detects malicious Intent"
          author = "Your Name"
        strings:
          $intent = "Intent.parseUri"
        condition:
          $intent
      }
    
    ```
 

```

snort
  alert tcp any any -> any any (msg:"Android Malicious Intent"; content:"Intent.parseUri"; sid:1000001;)

```
* **緩解措施**: 開發人員應該正確地驗證用戶輸入的 URI，並使用安全的隨機數生成器。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Intent (意圖)**: 一種 Android 的消息機制，允許應用程式之間進行通信。
* **URI (統一資源標誌)**: 一種用於識別資源的字符串，例如：網址。
* **java.util.Random (Java 隨機數生成器)**: 一種用於生成隨機數的 Java 類別。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/android-mental-health-apps-with-147m-installs-filled-with-security-flaws/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


