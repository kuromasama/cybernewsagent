---
layout: post
title:  "New OVSwrap Linux Kernel Flaw Lets Local Users Gain Root via Open vSwitch"
date:   2026-08-05 13:49:25 +0000
categories: [security]
severity: critical
---

# 🚨 解析 OVSwrap：Linux 核心 Open vSwitch 數據路徑記憶體破壞漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數: 7.8)
> * **受駭指標**: 本地權限提升 (LPE)
> * **關鍵技術**: 記憶體破壞、Netlink、Open vSwitch

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞源於 Linux 核心的 Open vSwitch 數據路徑中，對 Netlink 屬性的 `nla_len` 欄位進行了不安全的賦值。這個欄位是 16 位元寬，限制了單個嵌套屬性的大小為 65,535 個位元組。然而，在 2025 年 3 月的一個修改中，移除了對總生成動作流的 32 KiB 限制，從而暴露了舊的截斷漏洞。
* **攻擊流程圖解**:
  1. 攻擊者提交一個包含數百個 conntrack 子動作的 CLONE 動作。
  2. 在 x86-64 平台上，內核將每個子動作擴展為 164 個位元組，從而使生成的嵌套動作超過 65,535 個位元組。
  3. 當 OVS 將結果寫入 16 位元長度欄位時，值會溢出。
  4. 後續代碼相信這個長度並從攻擊者控制的 conntrack 數據中恢復解析，從而導致記憶體破壞。
* **受影響元件**: 受影響的版本包括 Linux 5.15.212 之前的版本、6.1.178 之前的版本、6.6.145 之前的版本、6.12.97 之前的版本、6.18.40 之前的版本和 7.1.5 之前的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要在目標系統上具有普通用戶權限，並且 Open vSwitch 數據路徑可用且未特權用戶命名空間已啟用。
* **Payload 建構邏輯**:

    ```
    
    python
      # 示例 Payload 結構
      payload = {
          'action': 'CLONE',
          'conntrack': [
              # conntrack 子動作
          ]
      }
    
    ```
  *範例指令*: 使用 `unshare` 命令創建私有用戶和網路命名空間，然後使用 `openvswitch` 命令提交 Payload。
* **繞過技術**: 如果目標系統已經安裝了 Open vSwitch 但尚未加載，攻擊者可以通過解析其通用 Netlink 家族名稱來自動加載它。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | (待補充) |
| IP | (待補充) |
| Domain | (待補充) |
| File Path | (待補充) |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule OVSwrap_Detection {
          meta:
              description = "Detect OVSwrap exploit"
              author = "Your Name"
          strings:
              $payload = { 00 01 02 03 } // 示例 Payload
          condition:
              $payload
      }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic)。
* **緩解措施**: 安裝已修補的供應商內核。如果 Open vSwitch 不需要，則最快的臨時步驟是阻止模組加載：

```

bash
  echo 'install openvswitch /bin/false' > /etc/modprobe.d/ovswrap.conf

```
  禁用未特權用戶命名空間可以關閉普通本地用戶路徑，但不能阻止已經具有 CAP_NET_ADMIN 權限的容器或其他進程。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Netlink**: 一種在 Linux 中用於內核和用戶空間之間通信的機制。它允許用戶空間程序與內核模組交換信息。
* **Open vSwitch**: 一種開源的虛擬交換機，允許在虛擬化環境中創建虛擬網路。
* **conntrack**: 連接跟蹤，一種用於跟蹤網路連接的機制。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/new-ovswrap-linux-kernel-flaw-lets.html)
- (若你知道相關的 MITRE ATT&CK 編號，請列出並附上連結)


