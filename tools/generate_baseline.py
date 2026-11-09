#!/usr/bin/env python3
"""Emit phpunit-baseline-tests.txt from origin/master test classes (with rename map)."""
import os, re, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAP = {
    "BackwardsCompatibilityTest": "Backwards_Compatibility_Test",
    "CoreTest": "Core_Test",
    "CryptoTest": "Crypto_Test",
    "CtrModeTest": "Ctr_Mode_Test",
    "EncodingTest": "Encoding_Test",
    "FileTest": "File_Test",
    "KeyTest": "Key_Test",
    "LegacyDecryptTest": "Legacy_Decrypt_Test",
    "PasswordTest": "Password_Test",
    "RuntimeTestTest": "Runtime_Test_Test",
}

def snake(s):
    s = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s)
    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', s)
    return s.lower()

master = subprocess.check_output(
    ['git', 'show', 'origin/master:test/unit'],
    cwd=ROOT,
    stderr=subprocess.DEVNULL,
)
# list files via git ls-tree
files = subprocess.check_output(
    ['git', 'ls-tree', '--name-only', 'origin/master', 'test/unit/'],
    cwd=ROOT,
    text=True,
).strip().splitlines()
lines = []
for fn in files:
    if not fn.endswith('.php'):
        continue
    content = subprocess.check_output(
        ['git', 'show', f'origin/master:{fn}'],
        cwd=ROOT,
        text=True,
    )
    cm = re.search(r'class\s+(\w+)', content)
    if not cm:
        continue
    cls = MAP.get(cm.group(1), cm.group(1))
    ns = ''
    nm = re.search(r'^\s*namespace\s+([^;]+);', content, re.M)
    if nm:
        ns = nm.group(1).strip() + '\\'
    fqcn = ns + cls
    for m in re.finditer(r'function\s+(test\w+)\s*\(', content):
        meth = snake(m.group(1))
        lines.append(f'{fqcn}::{meth}')

out = os.path.join(ROOT, 'scripts', 'phpunit-baseline-tests.txt')
with open(out, 'w') as f:
    f.write('# Baseline from origin/master unit tests (renamed identifiers)\n')
    for line in sorted(set(lines)):
        f.write(line + '\n')
print('wrote', out, 'count', len(set(lines)))
