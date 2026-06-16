---
layout: post
title:  "China-Linked SprySOCKS Backdoor Expands to Windows with Driver-Based Stealth"
date:   2026-06-16 10:59:06 +0000
categories: [security]
severity: critical
---

# 🚨 解析 SprySOCKS Windows 變體：魚叉攻擊的新進展

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Kernel Driver, TCP Traffic Diversion, WebSocket 通信

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: SprySOCKS Windows 變體（WIN_DRV 和 WIN_PLUS）利用 kernel driver 來隱藏其網路連接、進程、文件和登錄鍵。這使得傳統的安全軟件難以檢測到其存在。
* **攻擊流程圖解**:
  1. 初步入侵：攻擊者利用未知的初步入侵途徑（可能是 N-day 安全漏洞）獲得系統訪問權。
  2. Scheduled Task：創建並執行一個 scheduled task，以觸發 DLL side-loading 鏈，下載並執行 SprySOCKS 後門和驅動元件。
  3. Kernel Driver：WIN_DRV 變體使用 kernel driver（RawWNPF）來實現高級隱蔽性。
* **受影響元件**: Windows 10、Windows Server 2019 等版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有系統管理員權限。
* **Payload 建構邏輯**:

    ```
    
    python
      # 示例 Payload 結構
      payload = {
        "command": "execute",
        "args": ["cmd.exe", "/c", "whoami"]
      }
    
    ```
  *範例指令*：使用 `curl` 發送 WebSocket 請求：

```

bash
  curl -X POST \
  http://example.com/ws \
  -H 'Content-Type: application/json' \
  -d '{"command": "execute", "args": ["cmd.exe", "/c", "whoami"]}'

```
* **繞過技術**: WIN_DRV 變體可以實現 TCP 流量轉向，允許攻擊者通過隨機的 TCP 端口向後門發送命令，而不暴露後門的實際監聽端口。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | 1.2.3.4 | example.com | C:\Windows\Temp\RawWNPF.sys |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule SprySOCKS_WinDrv {
        meta:
          description = "Detects SprySOCKS Windows driver"
          author = "Your Name"
        strings:
          $s1 = "RawWNPF" ascii
          $s2 = "KW1B5206BDC1743FP.dat" ascii
        condition:
          all of them
      }
    
    ```
  或者是使用 Snort/Suricata Signature：

```

snort
  alert tcp any any -> any any (msg:"SprySOCKS WinDrv Detection"; content:"RawWNPF"; sid:1000001; rev:1;)

```
* **緩解措施**: 更新系統和應用程序至最新版本，關閉不必要的服務，限制系統管理員權限，並使用安全的通信協議（如 HTTPS）。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Kernel Driver (核心驅動)**: 一種運行在核心模式的驅動程序，能夠直接訪問硬件資源和系統內核。
* **TCP Traffic Diversion (TCP 流量轉向)**: 一種技術，允許攻擊者將 TCP 流量轉向到其他端口或 IP 地址，從而隱藏實際的通信。
* **WebSocket 通信**: 一種基於 TCP 的雙向實時通信協議，允許客戶端和服務器之間進行全雙工通信。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/china-linked-sprysocks-backdoor-expands.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1215/)


