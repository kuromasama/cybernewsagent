import os
import re

TARGET_DIR = "docs/_posts"

# 定義等級對應的正確 Emoji
ICON_MAP = {
    "critical": "🚨",  # Critical 維持警鈴 (或您可以改成其他)
    "high": "🔥",      # High 改成火焰
    "medium": "⚠️",    # Medium 改成警告
    "info": "🛡️"       # Info 改成盾牌
}

def fix_post_content(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. 抓取這篇文章的 Severity
    severity = "info" # 預設
    match = re.search(r'severity:\s*([a-zA-Z]+)', content)
    if match:
        severity = match.group(1).strip().lower()
    
    target_icon = ICON_MAP.get(severity, "🛡️")

    # 2. 替換邏輯：
    # 我們要找的是文章開頭常見的 "🚨 解析..." 或 "🚨 SIEM..."
    # 這裡我們把舊的通用警鈴 "🚨" 替換成 target_icon
    # 但為了避免誤殺 Critical (它本來就是 🚨)，我們先排除 critical
    
    if severity != "critical":
        # 如果不是 Critical，但內文卻有 🚨，就把它換掉
        if "🚨" in content:
            new_content = content.replace("🚨", target_icon)
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(new_content)
            print(f"✅ [Fixed] {os.path.basename(filepath)} -> 換成 {target_icon}")
            return

    print(f"💤 [Skip] {os.path.basename(filepath)} (無需變更)")

def main():
    print("🚀 開始修正舊文章的內文 Emoji...")
    for filename in os.listdir(TARGET_DIR):
        if filename.endswith(".md"):
            fix_post_content(os.path.join(TARGET_DIR, filename))
    print("🎉 修正完成！")

if __name__ == "__main__":
    main()