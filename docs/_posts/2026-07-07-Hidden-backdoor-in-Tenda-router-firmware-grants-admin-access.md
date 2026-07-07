---
layout: post
title:  "Hidden backdoor in Tenda router firmware grants admin access"
date:   2026-07-07 19:46:53 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Tenda 路由器隱藏驗證後門：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Unauthenticated Remote Code Execution (RCE)
> * **關鍵技術**: `MD5-based authentication`, `Undocumented authentication mechanism`, `Use-after-free`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Tenda 路由器的 `/bin/httpd` web server binary 中的 `login()` 函數存在一個未經文件記載的驗證機制。如果使用者嘗試登入，路由器會先進行標準的 MD5-based 驗證。如果驗證失敗，路由器會從 `sys.rzadmin.password` 配置值中取出一個替代密碼，並直接與遠端用戶提供的明文密碼進行比較。如果密碼匹配，設備將授予管理員 (role=2) 權限並創建一個有效的會話，無論用戶名為何。
* **攻擊流程圖解**:
  1. 用戶發送登入請求 -> `login()` 函數處理請求
  2. `login()` 函數進行 MD5-based 驗證 -> 驗證失敗
  3. `login()` 函數取出替代密碼 -> 比較替代密碼與用戶提供的明文密碼
  4. 密碼匹配 -> 授予管理員權限並創建有效會話
* **受影響元件**: Tenda 路由器的以下版本和設備：
  - US_FH1201V1.0BR_V1.2.0.14(408)_EN_TD – Tenda FH1201 (WiFi 路由器)
  - US_W15EV1.0br_V15.11.0.5(1068_1567_841)_EN_TDE – Tenda W15E (WiFi 路由器)
  - US_AC10V1.0re_V15.03.06.46_multi_TDE01 – Tenda AC10 (WiFi 路由器)
  - US_AC5V1.0RTL_V15.03.06.48_multi_TDE01 – Tenda AC5 (WiFi 路由器)
  - US_AC6V2.0RTL_V15.03.06.51_multi_T – Tenda AC6 V2 (WiFi 路由器)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 無需任何權限或網路位置限制
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義替代密碼
    alternate_password = "your_alternate_password"
    
    # 定義登入請求
    login_request = {
        "username": "any_username",
        "password": alternate_password
    }
    
    # 發送登入請求
    response = requests.post("http://tenda_router_ip/login", data=login_request)
    
    # 檢查是否登入成功
    if response.status_code == 200:
        print("登入成功")
    else:
        print("登入失敗")
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 URL 編碼或 Base64 編碼來隱藏替代密碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | Tenda 路由器 IP |
| Domain | Tenda 路由器域名 |
| File Path | `/bin/httpd` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Tenda_Backdoor {
      meta:
        description = "Tenda 路由器隱藏驗證後門"
        author = "Your Name"
      strings:
        $a = "sys.rzadmin.password"
      condition:
        $a
    }
    
    ```
* **緩解措施**: 除了更新修補之外，還可以修改路由器的配置文件以禁用遠端登入功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **MD5-based authentication**: 一種使用 MD5 雜湊演算法進行密碼驗證的機制。
* **Undocumented authentication mechanism**: 一種未經文件記載的驗證機制。
* **Use-after-free**: 一種記憶體漏洞，指的是程式在釋放記憶體後仍然嘗試使用該記憶體。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/hidden-backdoor-in-tenda-router-firmware-grants-admin-access/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


