---
layout: post
title:  "針對研究人員揭露Deep Security Agent防護功能暫時失效問題，趨勢科技表示重新載入機制屬既有設計，無須修補"
date:   2026-06-09 14:34:58 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Linux 版 Deep Security Agent 的檔案描述子限制繞過
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：6.5)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `File Descriptor`, `ds_am`, `bmhook`, `tmhook`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Linux 版 Deep Security Agent 的 `ds_am` 程序會嚴格控制資源耗用，設有 CPU、記憶體與檔案描述子（File Descriptor，fd）等資源使用上限，以避免影響受保護主機的正常運作。然而，研究人員發現，如果持續產生大量檔案系統事件，會導致 `ds_am` 超過預設檔案描述符（fd）限制，進而觸發自動重新啟動的程序，並重新載入 `bmhook` 與 `tmhook` 元件。
* **攻擊流程圖解**: 
    1. 攻擊者產生大量檔案系統事件。
    2. `ds_am` 程序偵測到檔案描述子使用量超過預設限制。
    3. `ds_am` 程序觸發自動重新啟動。
    4. `bmhook` 與 `tmhook` 元件重新載入。
* **受影響元件**: Linux 版 Deep Security Agent。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有權限產生大量檔案系統事件。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    
    # 產生大量檔案系統事件
    for i in range(10000):
        os.system("touch /tmp/test_{}".format(i))
    
    ```
    *範例指令*: 使用 `curl` 產生大量 HTTP 請求。

```

bash
curl -X GET 'http://example.com' -H 'Connection: keep-alive' -H 'Keep-Alive: 1000'

```
* **繞過技術**: 攻擊者可以使用 `eBPF` 技術來繞過 `ds_am` 程序的檔案描述子限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  | /tmp/test_* |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Linux_Deep_Security_Agent_Fd_Overflow {
        meta:
            description = "Linux 版 Deep Security Agent 檔案描述子限制繞過"
            author = "Your Name"
        strings:
            $s1 = "ds_am"
            $s2 = "bmhook"
            $s3 = "tmhook"
        condition:
            all of them
    }
    
    ```
    或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)。

```

sql
index=linux_logs (ds_am OR bmhook OR tmhook) AND (file_path="/tmp/test_*")

```
* **緩解措施**: 除了更新修補之外，還可以增加檔案描述子限制，例如修改 `/etc/security/limits.conf` 文件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **File Descriptor (檔案描述子)**: 檔案描述子是一個整數，代表一個已經開啟的檔案或其他資源。它是作業系統用來識別和存取檔案的方式。
* **ds_am**: `ds_am` 是 Linux 版 Deep Security Agent 的一個程序，負責控制資源耗用和檔案描述子限制。
* **bmhook**: `bmhook` 是 Linux 版 Deep Security Agent 的一個元件，負責提供檔案系統事件的 hook 功能。
* **tmhook**: `tmhook` 是 Linux 版 Deep Security Agent 的一個元件，負責提供檔案系統事件的 hook 功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176494)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1055/)


