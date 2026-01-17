
import os
import re

TARGET_DIR = "docs/_posts/"

def fix_table_formatting(content):
    """
    Applies three fixes to Markdown tables in the given string content:
    1. Ensures a blank line exists before a table.
    2. Removes leading indentation from all table lines.
    3. Rebuilds the separator line to be standard.
    """

    # Fix 1: Ensure there's a blank line before a potential table.
    # This looks for a non-newline char followed by a newline and then a line starting with a pipe (possibly indented).
    content = re.sub(r'([^\n])\n([ \t]*\|)', r'\1\n\n\2', content)

    # Regex to find a complete markdown table block.
    # A table is one or more consecutive lines starting with optional whitespace and a pipe.
    table_pattern = r"(?:^[ \t]*\|.*(?:\n|$))+"

    def process_table_block(match):
        """
        Processes a single matched table block.
        """
        table_text = match.group(0)

        # Split into lines and strip trailing whitespace from the block
        lines = table_text.strip().split('\n')

        # Fix 2: Remove leading whitespace (indentation) from each line.
        processed_lines = [line.lstrip() for line in lines]

        # Fix 3: Standardize the separator line.
        if len(processed_lines) > 1:
            header = processed_lines[0]
            # Count columns from the header by splitting by pipe and filtering empty strings.
            num_columns = len([cell for cell in header.split('|') if cell.strip()])

            if num_columns > 0:
                # Create a standard GitHub-flavored Markdown separator, e.g., |---|---|
                separator = '|' + '---|' * num_columns
                processed_lines[1] = separator

        return '\n'.join(processed_lines)

    # Apply the block-level fixes to all found tables.
    fixed_content = re.sub(table_pattern, process_table_block, content, flags=re.MULTILINE)
    return fixed_content

def main():
    """
    Main function to scan and fix all Markdown files in the target directory.
    """
    print(f"🚀 Starting Markdown table fix in '{TARGET_DIR}'...")
    files_scanned = 0
    files_fixed = 0
    
    if not os.path.isdir(TARGET_DIR):
        print(f"❌ Error: Directory not found at '{TARGET_DIR}'")
        return

    for filename in os.listdir(TARGET_DIR):
        if filename.endswith(".md"):
            files_scanned += 1
            filepath = os.path.join(TARGET_DIR, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    original_content = f.read()

                fixed_content = fix_table_formatting(original_content)

                if fixed_content != original_content:
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(fixed_content)
                    print(f"✅ Fixed: {filename}")
                    files_fixed += 1
            except Exception as e:
                print(f"❌ Error processing {filename}: {e}")

    print("-" * 30)
    print(f"📊 Total files scanned: {files_scanned}")
    print(f"🛠️ Files fixed: {files_fixed}")
    print("🎉 Done!")

if __name__ == "__main__":
    main()
