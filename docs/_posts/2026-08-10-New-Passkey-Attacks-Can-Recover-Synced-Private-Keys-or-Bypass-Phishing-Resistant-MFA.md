---
layout: post
title:  "New Passkey Attacks Can Recover Synced Private Keys or Bypass Phishing-Resistant MFA"
date:   2026-08-10 12:52:13 +0000
categories: [security]
severity: high
---

# 🔥 解析 Passkey 防護繞過技術：利用漏洞實現身份驗證
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：6.5)
> * **受駭指標**: 身份驗證繞過
> * **關鍵技術**: Passkey、Windows Hello for Business、FIDO2

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Windows 存儲過去的 YubiKey 簽名在明文中，允許已驗證的非特權用戶（包括遠程用戶）讀取。這些簽名可以與 Microsoft Entra ID 的 Passkey 驗證弱點結合，實現特權用戶的模擬，儘管需要防釣魚的多因素驗證。
* **攻擊流程圖解**:
  1. 攻擊者獲得已驗證用戶的簽名。
  2. 攻擊者使用簽名和 Microsoft Entra ID 的弱點，模擬特權用戶。
* **受影響元件**: Windows 10、Windows 11 和 Windows Server。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得已驗證用戶的簽名。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 獲取簽名
    signature = "簽名內容"
    
    # 模擬特權用戶
    url = "https://example.com/privileged-user"
    headers = {
        "Authorization": f"Bearer {signature}"
    }
    response = requests.get(url, headers=headers)
    
    # 驗證是否成功
    if response.status_code == 200:
        print("模擬成功")
    else:
        print("模擬失敗")
    
    ```
* **繞過技術**: 攻擊者可以使用已驗證用戶的簽名，模擬特權用戶，繞過防釣魚的多因素驗證。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Passkey_Attack {
      meta:
        description = "Passkey 攻擊偵測"
      strings:
        $signature = "簽名內容"
      condition:
        $signature
    }
    
    ```
* **緩解措施**: 更新 Windows 安全補丁，啟用防釣魚的多因素驗證，限制已驗證用戶的簽名存儲。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Passkey**: 一種基於 FIDO2 的身份驗證技術，使用公鑰加密和私鑰解密。
* **FIDO2**: 一種基於公鑰加密的身份驗證標準，提供防釣魚的多因素驗證。
* **Windows Hello for Business**: 一種基於 FIDO2 的身份驗證技術，使用 Windows Hello 的生物識別和 PIN 碼驗證。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/new-passkey-attacks-can-recover-synced.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1556/)


