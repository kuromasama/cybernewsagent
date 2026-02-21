---
layout: post
title:  "Predator spyware hooks iOS SpringBoard to hide mic, camera activity"
date:   2026-02-21 18:25:34 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Intellexa Predator Spyware 對 iOS 的隱蔽錄音指標攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 隱蔽錄音指標（RCE）
> * **關鍵技術**: Hook 函數、SpringBoard、Sensor ActivityDataProvider

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Predator Spyware 利用先前獲得的 kernel-level 存取權限，hook SpringBoard 中的 `HiddenDot::setupHook()` 函數，攔截 sensor 活動更新，防止錄音指標顯示。
* **攻擊流程圖解**:
  1. Predator Spyware 獲得 kernel-level 存取權限
  2. Hook SpringBoard 中的 `HiddenDot::setupHook()` 函數
  3. 攔截 sensor 活動更新
  4. 防止錄音指標顯示
* **受影響元件**: iOS 14 或以上版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: kernel-level 存取權限
* **Payload 建構邏輯**:

    ```
    
    objectivec
      // Hook 函數
      void HiddenDot::setupHook() {
        // 攔截 sensor 活動更新
        SBSensorActivityDataProvider *provider = [SBSensorActivityDataProvider sharedInstance];
        [provider hookSensorActivityUpdates];
      }
    
    ```
 

```

bash
  # 範例指令
  curl -X POST \
  https://example.com/predator \
  -H 'Content-Type: application/json' \
  -d '{"action": "start_recording"}'

```
* **繞過技術**: Predator Spyware 利用 ARM64 指令集和 Pointer Authentication Code (PAC) 重新導向來繞過 camera 權限檢查

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | 192.168.1.100 | example.com | /private/var/mobile/Library/Preferences/com.example.app.plist |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Predator_Spyware {
        meta:
          description = "Detect Predator Spyware"
          author = "Your Name"
        strings:
          $a = "HiddenDot::setupHook"
        condition:
          $a
      }
    
    ```
 

```

spl
  index=main sourcetype=ios_logs (eventtype="camera_access" OR eventtype="microphone_access") | stats count as num_access by src_ip | where num_access > 5

```
* **緩解措施**: 更新 iOS 至最新版本，關閉不必要的 camera 和 microphone 權限

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Hook 函數**: 一種技術，允許程式攔截和修改其他程式的行為。
* **SpringBoard**: iOS 中的桌面管理程式，負責管理應用程式和桌面。
* **Sensor ActivityDataProvider**: 一種提供 sensor 活動更新的程式，允許應用程式接收 sensor 活動的通知。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/predator-spyware-hooks-ios-springboard-to-hide-mic-camera-activity/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


