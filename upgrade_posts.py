import os
import re

TARGET_DIR = "docs/_posts"

def upgrade_post(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. 檢查是否已經有 severity 設定
    if "severity: " in content.split("---")[1]:
        print(f"⏩ 跳過 (已有設定): {os.path.basename(filepath)}")
        return

    # 2. 搜尋嚴重等級關鍵字
    # 支援中文 "嚴重等級: Critical" 或英文 "**Severity**: High"
    severity = "info"
    match = re.search(r'\*\*(嚴重等級|Severity)\*\*:\s*([a-zA-Z\u4e00-\u9fa5]+)', content, re.IGNORECASE)
    
    if match:
        level_text = match.group(2).strip().lower()
        level_map = {
            "極高": "critical", "critical": "critical",
            "嚴重": "critical",
            "高": "high", "high": "high",
            "中": "medium", "medium": "medium",
            "低": "info", "low": "info", "info": "info"
        }
        severity = level_map.get(level_text, "info")

    # 3. 插入到 Front Matter
    # 找到第二個 "---" 的位置
    parts = content.split("---", 2)
    if len(parts) >= 3:
        front_matter = parts[1]
        body = parts[2]
        
        # 加入 severity 欄位
        new_front_matter = front_matter.rstrip() + f"\nseverity: {severity}\n"
        
        new_content = "---" + new_front_matter + "---" + body
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(new_content)
        print(f"✅ 已升級 [{severity.upper()}]: {os.path.basename(filepath)}")
    else:
        print(f"❌ 格式錯誤: {os.path.basename(filepath)}")

def main():
    print("🚀 開始升級舊文章 Front Matter...")
    for filename in os.listdir(TARGET_DIR):
        if filename.endswith(".md"):
            upgrade_post(os.path.join(TARGET_DIR, filename))
    print("🎉 升級完成！")

if __name__ == "__main__":
    main()