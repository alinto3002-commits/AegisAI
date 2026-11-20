import ast
import re

def remediate_syntax_error(language: str, error_message: str, faulty_line: str, lines: list, err_line: int) -> str:
    line_clean = faulty_line.strip()
    
    if language == "python":
        # Check for corrupted docstring or string
        if line_clean.startswith('"""') or line_clean.startswith("'''"):
            q = '"""' if line_clean.startswith('"""') else "'''"
            content = line_clean.lstrip('"\'').rstrip('"\':; ')
            line_clean = f'{q}{content}{q}'
        elif re.search(r'[:;]+$', line_clean) and not any(line_clean.startswith(kw) for kw in ['def ', 'class ', 'if ', 'elif ', 'else', 'try', 'except', 'finally', 'while ', 'for ', 'with ']):
            line_clean = re.sub(r'[:;]+$', '', line_clean).strip()
        elif any(line_clean.startswith(kw) for kw in ['def ', 'class ', 'if ', 'elif ', 'else', 'try', 'except', 'finally', 'while ', 'for ', 'with ']):
            if not line_clean.endswith(':'):
                line_clean = line_clean.rstrip(';') + ':'

        # Determine appropriate indentation
        target_indent = ""
        for i in range(err_line - 2, -1, -1):
            if i < len(lines) and lines[i].strip():
                prev = lines[i]
                prev_indent = re.match(r'^\s*', prev).group(0)
                if prev.strip().endswith(':'):
                    target_indent = prev_indent + '    '
                else:
                    target_indent = prev_indent
                break
        
        return target_indent + line_clean
    else:
        # Java
        if not line_clean.endswith(';') and not line_clean.endswith('{') and not line_clean.endswith('}') and not line_clean.startswith('//') and not line_clean.startswith('/*') and not line_clean.startswith('*'):
            line_clean += ';'
        target_indent = ""
        for i in range(err_line - 2, -1, -1):
            if i < len(lines) and lines[i].strip():
                target_indent = re.match(r'^\s*', lines[i]).group(0)
                break
        return target_indent + line_clean

# Test with the exact error from the screenshot
code = '''def read_user_file(filename):
        """Brief summary of function purpose (PEP 257).":;
    return None'''

lines = code.split('\n')
err_line = 2
faulty_line = lines[err_line - 1]
fixed = remediate_syntax_error("python", "unexpected indent at line 2, column 8", faulty_line, lines, err_line)
print("Fixed line:", repr(fixed))
lines[err_line - 1] = fixed
result_code = '\n'.join(lines)
print("Result Code:\n" + result_code)
ast.parse(result_code)
print("SUCCESS: Valid Python syntax!")
