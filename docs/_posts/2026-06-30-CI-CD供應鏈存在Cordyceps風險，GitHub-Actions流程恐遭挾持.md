---
layout: post
title:  "CI/CD供應鏈存在Cordyceps風險，GitHub Actions流程恐遭挾持"
date:   2026-06-30 09:23:27 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Cordyceps：CI/CD 供應鏈風險利用與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `GitHub Actions`, `CI/CD`, `Supply Chain Attack`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Cordyceps 風險源於 GitHub Actions 的自動化流程設計與維護上的安全缺陷。當流程把外部使用者可控制的內容視為可信資料，就可能讓攻擊者借用專案原本授予自動化系統的權限。
* **攻擊流程圖解**: 
    1. 攻擊者提交惡意程式碼到 GitHub 儲存庫。
    2. GitHub Actions 自動化流程執行，將惡意程式碼視為可信資料。
    3. 惡意程式碼被執行，攻擊者獲得 RCE 權限。
* **受影響元件**: GitHub Actions、GitHub 儲存庫。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 GitHub 帳號和提交程式碼的權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    
    # 惡意程式碼
    def malicious_code():
        # 執行系統命令
        os.system("echo 'Hello, World!' > /tmp/malicious_file")
    
    # 提交惡意程式碼到 GitHub
    github_repo = "https://github.com/example/repo"
    commit_message = "Add malicious code"
    
    ```
    *範例指令*: 使用 `curl` 提交惡意程式碼到 GitHub。

```

bash
curl -X POST \
  https://api.github.com/repos/example/repo/contents/path/to/file \
  -H 'Authorization: Bearer YOUR_GITHUB_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"message":"Add malicious code","content":"YOUR_MALICIOUS_CODE"}'

```
* **繞過技術**: 攻擊者可以使用 GitHub Actions 的 `env` 變數來繞過安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `abc123` | `192.168.1.100` | `example.com` | `/tmp/malicious_file` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_code {
        meta:
            description = "Detect malicious code"
            author = "Your Name"
        strings:
            $a = "echo 'Hello, World!' > /tmp/malicious_file"
        condition:
            $a
    }
    
    ```
    或者是使用 Snort/Suricata Signature：

```

snort
alert tcp any any -> any any (msg:"Malicious code detected"; content:"echo 'Hello, World!' > /tmp/malicious_file"; sid:1000001; rev:1;)

```
* **緩解措施**: 
    1. 更新 GitHub Actions 的安全設定。
    2. 使用安全的提交流程。
    3. 監控 GitHub Actions 的執行記錄。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **CI/CD (Continuous Integration/Continuous Deployment)**: 一種軟體開發流程，自動化測試、建置、部署和發布。
* **GitHub Actions**: 一種自動化流程工具，讓開發者可以自動化軟體開發流程。
* **Supply Chain Attack**: 一種攻擊方式，攻擊者透過供應鏈中的弱點來攻擊目標系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176978)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


