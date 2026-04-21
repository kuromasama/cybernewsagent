---
layout: post
title:  "AI推論框架SGLang曝RCE漏洞，惡意GGUF模型可觸發任意程式碼執行"
date:   2026-04-21 13:10:23 +0000
categories: [security]
severity: critical
---

# 🚨 解析 SGLang RCE 漏洞：CVE-2026-5760 技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: 遠端程式碼執行（RCE）
> * **關鍵技術**: Jinja2 模板注入、SSTI（Server-Side Template Injection）

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: SGLang 的重新排序（Reranking）功能端點 `/v1/rerank` 未經沙箱限制的設定，導致模型檔中的 `chat_template` 可以跳脫原有執行限制，在伺服器上執行任意 Python 程式碼。
* **攻擊流程圖解**:
  1. 攻擊者製作內含惡意 Jinja2 模板注入的 GGUF 模型檔。
  2. 受害者將模型檔載入 SGLang。
  3. 攻擊者發送請求至 `/v1/rerank` 端點。
  4. SGLang 執行模型檔中的 `chat_template`，導致任意 Python 程式碼執行。
* **受影響元件**: SGLang 版本未指定，但所有使用 `/v1/rerank` 端點的部署均屬高風險環境。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要將惡意模型檔上傳至受害者的 SGLang 伺服器。
* **Payload 建構邏輯**:

    ```
    
    python
    # 惡意 Jinja2 模板注入示例
    chat_template = """
    {% set payload = 'import os; os.system("echo Hello, World!")' %}
    {{ payload | eval }}
    """
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -X POST \
      http://example.com/v1/rerank \
      -H 'Content-Type: application/json' \
      -d '{"model": {"tokenizer": {"chat_template": "' + chat_template + '"}}}'
    
    ```
* **繞過技術**: 攻擊者可以使用 SSTI 繞過技術，例如使用 `{{ request.application.__config__.items() }}` 獲取伺服器的配置信息。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule SGLang_RCE {
      meta:
        description = "SGLang RCE 漏洞偵測"
      strings:
        $jinja_template = "{% set payload = 'import os; os.system(\"echo Hello, World!\")' %}"
      condition:
        $jinja_template
    }
    
    ```
* **緩解措施**:
  1. 將 `_get_jinja_env()` 函式中的 `jinja2.Environment()` 替換為 `ImmutableSandboxedEnvironment`。
  2. 暫時關閉 `/v1/rerank` 端點。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Jinja2 模板注入 (SSTI)**: 惡意的 Jinja2 模板注入，可以導致任意 Python 程式碼執行。
* **Server-Side Template Injection (SSTI)**: 伺服器端模板注入，允許攻擊者注入惡意模板代碼。
* **ImmutableSandboxedEnvironment**: 一種安全的 Jinja2 環境，限制了模板的執行權限。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://www.ithome.com.tw/news/175219)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


