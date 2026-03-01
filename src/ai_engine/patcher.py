import os
import re

def apply_fixes(report_md: str, project_root: str) -> dict:
    summary = {"successful": [], "failed": []}
    
    # Split the report by vulnerability sections (starting with "## [")
    sections = re.split(r'^## \[', report_md, flags=re.MULTILINE)[1:]
    
    for section in sections:
        # Extract file path from Scope
        scope_match = re.search(r'\*\*Scope:\*\*\s*- `([^`]+)`', section)
        if not scope_match:
            continue
            
        file_path_str = scope_match.group(1).strip()
        
        # Extract the diff block
        diff_match = re.search(r'### Recommended Mitigation\s*```diff\n(.*?)\n```', section, re.DOTALL)
        if not diff_match:
            continue
            
        diff_content = diff_match.group(1)
        
        lines_to_remove = []
        lines_to_add = []
        
        has_changes = False
        for line in diff_content.split('\n'):
            if line.startswith('-'):
                lines_to_remove.append(line[1:])
                has_changes = True
            elif line.startswith('+'):
                lines_to_add.append(line[1:])
                has_changes = True
            else:
                # Context lines
                val = line[1:] if line.startswith(' ') else line
                lines_to_remove.append(val)
                lines_to_add.append(val)
                
        if not has_changes:
            continue
            
        target_block = "\n".join(lines_to_remove)
        replacement_block = "\n".join(lines_to_add)
        
        abs_path = file_path_str
        if not os.path.isabs(abs_path):
            abs_path = os.path.join(project_root, file_path_str)
            
        if not os.path.exists(abs_path):
            summary["failed"].append((file_path_str, "File not found locally"))
            continue
            
        try:
            with open(abs_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            if target_block in content:
                new_content = content.replace(target_block, replacement_block, 1)
                with open(abs_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                summary["successful"].append(file_path_str)
            else:
                # Fallback: attempt match after stripping trailing newlines/spaces
                if target_block.strip() in content:
                    new_content = content.replace(target_block.strip(), replacement_block.strip(), 1)
                    with open(abs_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    summary["successful"].append(file_path_str)
                else:
                    summary["failed"].append((file_path_str, "Code block mismatch (could not find the exact chunk to remove)"))
        except Exception as str_e:
            summary["failed"].append((file_path_str, str(str_e)))

    return summary
