---
layout: default
title: 資安戰情室
---

# 🛡️ 最新資安威脅情報
> 由 AI 驅動的自動化資安分析與紅藍隊演練報告。

---

## 📋 最新文章列表

<ul>
  {% for post in site.posts %}
    <li style="margin-bottom: 15px;">
      <span style="color: #666; font-size: 0.9em;">{{ post.date | date: "%Y-%m-%d" }}</span><br>
      <a href="{{ post.url | relative_url }}" style="font-size: 1.2em; font-weight: bold;">{{ post.title }}</a>
    </li>
  {% endfor %}
</ul>