---
layout: post
title:  "FortiBleed campaign used custom FortiGate sniffer to steal credentials"
date:   2026-06-22 20:37:30 +0000
categories: [security]
severity: critical
---

# 🚨 FortiBleed 攻擊：解析 FortiGate 設備的驗證機密竊取

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak (驗證機密竊取)
> * **關鍵技術**: `FortiOS`, `Golang`, `Sniffer`, `Credential Harvesting`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: FortiGate 設備的 FortiOS 系統中，存在一個診斷嗅探器（diagnose sniffer）功能，允許管理員在設備上監控網路流量。然而，這個功能也可以被攻擊者利用來竊取驗證機密。
* **攻擊流程圖解**:
  1. 攻擊者使用 `credential stuffing` 和 `brute-force attacks` 獲得 FortiGate 設備的管理員權限。
  2. 攻擊者部署一個自定義的嗅探器工具（FortigateSniffer）在受感染的 FortiGate 設備上。
  3. 嗅探器工具使用 FortiOS 的診斷嗅探器功能來監控網路流量，並竊取驗證機密（例如：RADIUS、NTLM、Kerberos、LDAP 等協議的驗證資料）。
  4.竊取的驗證機密被傳送到攻擊者的伺服器進行處理和分析。
* **受影響元件**: FortiGate 設備的 FortiOS 系統，版本號未指定。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 FortiGate 設備的管理員權限。
* **Payload 建構邏輯**:

    ```
    
    go
    // FortigateSniffer 工具的簡化版本
    package main
    
    import (
    	"fmt"
    	"net"
    )
    
    func main() {
    	// 建立 FortiGate 設備的連線
    	conn, err := net.Dial("tcp", "fortigate_ip:22")
    	if err != nil {
    		fmt.Println(err)
    		return
    	}
    
    	// 執行診斷嗅探器命令
    	cmd := "diagnose sniffer packet"
    	_, err = conn.Write([]byte(cmd))
    	if err != nil {
    		fmt.Println(err)
    		return
    	}
    
    	// 讀取嗅探器的輸出
    	buf := make([]byte, 1024)
    	n, err := conn.Read(buf)
    	if err != nil {
    		fmt.Println(err)
    		return
    	}
    
    	// 處理嗅探器的輸出
    	fmt.Println(string(buf[:n]))
    }
    
    ```
* **繞過技術**: 攻擊者可以使用 `WAF` 繞過技巧來隱藏自己的 IP 地址和流量。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule FortigateSniffer {
      meta:
        description = "FortigateSniffer 嗅探器工具"
        author = "Your Name"
      strings:
        $a = "diagnose sniffer packet"
      condition:
        $a
    }
    
    ```
* **緩解措施**: 更新 FortiGate 設備的 FortiOS 系統，使用強密碼和多因素驗證，限制管理員權限，監控網路流量和系統日誌。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **FortiOS**: FortiGate 設備的操作系統。
* **Sniffer**: 一種網路流量監控工具。
* **Credential Harvesting**: 驗證機密竊取技術。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/fortibleed-campaign-used-custom-fortigate-sniffer-to-steal-credentials/)
- [MITRE ATT&CK](https://attack.mitre.org/)


