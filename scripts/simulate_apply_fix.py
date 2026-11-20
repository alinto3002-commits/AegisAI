import sys
sys.path.insert(0, '.')
from backend.agents.orchestrator import MultiAgentOrchestrator
from backend.models.schemas import CodeSubmission

def simulate_js_apply_fix(code_str, finding):
    lines = code_str.split('\n')
    raw_snippet = (finding.remediation.corrected_snippet or '').strip('\r\n')
    
    # Strip comments (#, //, /*, *, */)
    non_comment = [l for l in raw_snippet.split('\n') if not l.strip().startswith(('#', '//', '/*', '*', '*/'))]
    corrected = ('\n'.join(non_comment) if non_comment else raw_snippet).strip('\r\n')

    raw_ev = (finding.evidence or '').strip()
    raw_orig = (finding.remediation.original_snippet or '').strip()
    
    # Target line index lookup
    target_idx = -1
    if raw_ev:
        if '********' in raw_ev and '=' in raw_ev:
            var_part = raw_ev.split('=')[0].strip()
            target_idx = next((i for i, l in enumerate(lines) if var_part in l), -1)
        if target_idx == -1:
            target_idx = next((i for i, l in enumerate(lines) if raw_ev in l), -1)
        if target_idx == -1:
            target_idx = next((i for i, l in enumerate(lines) if l.strip() == raw_ev or l.strip().startswith(raw_ev)), -1)
            
    if target_idx == -1 and raw_orig:
        target_idx = next((i for i, l in enumerate(lines) if raw_orig in l or l.strip() == raw_orig), -1)
        
    if target_idx == -1 and finding.line_start:
        target_idx = finding.line_start - 1
        
    if target_idx < 0 or target_idx >= len(lines):
        return code_str, False

    if finding.id and finding.id.startswith('SYNTAX'):
        replacement = corrected
    else:
        base_indent = ""
        for char in lines[target_idx]:
            if char in (' ', '\t'):
                base_indent += char
            else:
                break

        # If line starts with '}' and corrected starts with 'catch', ensure delimiter
        if lines[target_idx].strip().startswith('}') and not corrected.startswith('}'):
            corrected = '} ' + corrected

        corr_lines = corrected.split('\n')
        non_empty = [len(l) - len(l.lstrip()) for l in corr_lines if l.strip()]
        min_indent = min(non_empty) if non_empty else 0

        formatted = []
        for l in corr_lines:
            if not l.strip():
                formatted.append('')
            else:
                rel = l[min_indent:]
                formatted.append(base_indent + rel)
        replacement = '\n'.join(formatted)

    span = 1
    if finding.line_end and finding.line_end >= finding.line_start:
        span = finding.line_end - finding.line_start + 1

    if not corrected:
        new_lines = lines[:target_idx] + lines[target_idx + span:]
    else:
        new_lines = lines[:target_idx] + [replacement] + lines[target_idx + span:]
    return '\n'.join(new_lines), True

orch = MultiAgentOrchestrator()

# Test Python Vulnerable Sample
print('=== TESTING PYTHON APPLY FIX SEQUENCE ===')
code = open('backend/test_samples/python/vulnerable_sqli_secrets.py').read()

# Apply fixes in a loop until clean or stuck
for step in range(12):
    rep = orch.analyze(CodeSubmission(code=code, language='python', filename='vulnerable_sqli_secrets.py'))
    print(f'Step {step}: Findings = {len(rep.findings)}, Health Score = {rep.health_score}, Verdict = {rep.verdict}')
    if not rep.findings or rep.health_score >= 100:
        print('SUCCESS: Reached clean code!')
        break
    
    # Pick first actionable finding with remediation
    target_f = None
    for f in rep.findings:
        if f.remediation and f.remediation.corrected_snippet is not None:
            target_f = f
            break
            
    if not target_f:
        print('No more actionable findings.')
        break
        
    print(f'  -> Applying fix for: {target_f.title} (line {target_f.line_start})')
    code, ok = simulate_js_apply_fix(code, target_f)
    if not ok:
        print('  FAILED to apply fix!')
        break
