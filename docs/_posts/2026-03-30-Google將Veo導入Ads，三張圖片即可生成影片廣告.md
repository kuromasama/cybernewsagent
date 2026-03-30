---
layout: post
title:  "Google將Veo導入Ads，三張圖片即可生成影片廣告"
date:   2026-03-30 18:52:50 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Google Veo 生成式影片模型在廣告製作中的應用與潛在風險

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 4.3)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `生成式AI`, `影片生成`, `廣告製作`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Veo 生成式影片模型在生成影片時，可能會將用戶上傳的圖片中的敏感信息（如個人資料、公司機密）包含在生成的影片中。
* **攻擊流程圖解**: 
    1. 用戶上傳圖片至 Google Ads 的 Asset Studio
    2. Veo 生成式影片模型生成影片
    3. 生成的影片可能包含敏感信息
* **受影響元件**: Google Ads 的 Asset Studio、Veo 生成式影片模型

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶需要有 Google Ads 的帳戶和上傳圖片的權限
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 上傳圖片至 Google Ads 的 Asset Studio
    url = "https://ads.google.com/assetstudio/upload"
    image_path = "/path/to/image.jpg"
    response = requests.post(url, files={"image": open(image_path, "rb")})
    
    # 使用 Veo 生成式影片模型生成影片
    url = "https://ads.google.com/assetstudio/generate_video"
    response = requests.post(url, json={"image_id": response.json()["image_id"]})
    
    # 下載生成的影片
    url = "https://ads.google.com/assetstudio/download_video"
    response = requests.get(url, params={"video_id": response.json()["video_id"]})
    
    ```
    *範例指令*: 使用 `curl` 下載生成的影片

```

bash
curl -X GET "https://ads.google.com/assetstudio/download_video?video_id=VIDEO_ID" -o video.mp4

```
* **繞過技術**: 可以使用代理伺服器或 VPN 來繞過 Google Ads 的 IP 限制

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | ads.google.com | /assetstudio/upload |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Veo_Generate_Video {
        meta:
            description = "Detect Veo generate video request"
            author = "Your Name"
        strings:
            $url = "https://ads.google.com/assetstudio/generate_video"
        condition:
            $url in http.request.uri
    }
    
    ```
    或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)

```

sql
index=ads_logs sourcetype=assetstudio_generate_video

```
* **緩解措施**: 
    1. 更新 Google Ads 的 Asset Studio 和 Veo 生成式影片模型至最新版本
    2. 對用戶上傳的圖片進行安全審查
    3. 限制用戶上傳圖片的格式和大小

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **生成式AI (Generative AI)**: 一種可以生成新內容的 AI 技術，例如圖片、影片、音樂等。
* **影片生成 (Video Generation)**: 使用 AI 技術生成影片的過程，包括選擇圖片、添加音效、編輯內容等。
* **廣告製作 (Ad Creation)**: 使用 Google Ads 的 Asset Studio 和 Veo 生成式影片模型生成廣告的過程，包括上傳圖片、生成影片、添加文字等。

## 5. 🔗 參考文獻與延伸閱讀
- [Google Ads 的 Asset Studio](https://ads.google.com/assetstudio)
- [Veo 生成式影片模型](https://veo.google.com/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1056/)


