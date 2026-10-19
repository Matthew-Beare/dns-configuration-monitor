"""Sanity-check publishable source and losslessly reconstructed screenshots."""
from pathlib import Path
import re
import struct

ROOT=Path(__file__).resolve().parent
SENSITIVE=[
    re.compile(r"(?i)(?:student-repos|\bd522\b|\bwgu\.internal\b|\b[0-9]{9}\b)"),
    re.compile(r"(?i)(?:AutoAddPolicy\s*\(|http://helpdesk\.|TOKEN\s*=\s*['\"][^\'\"]{8,})"),
    re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
]
text_files=[]
for file in ROOT.rglob('*'):
    if not file.is_file() or '__pycache__' in file.parts or '.git' in file.parts:continue
    if file.suffix.lower() in ('.py','.json','.md','.yml','.yaml','.txt','.csv') or file.name=='.gitignore':
        text_files.append(file)
        if file==Path(__file__):continue  # Scanner rule definitions aren't exposure.
        s=file.read_text(encoding='utf-8')
        for pattern in SENSITIVE:
            if pattern.search(s):raise AssertionError('Forbidden publication text in '+str(file.relative_to(ROOT)))

def png_chunks(file):
    b=file.read_bytes()
    if not b.startswith(bytes.fromhex('89504e470d0a1a0a')):raise AssertionError('Invalid PNG: '+file.name)
    pos=8;types=[]
    while pos<len(b):
        if pos+12>len(b):raise AssertionError('Truncated PNG')
        length=struct.unpack('>I',b[pos:pos+4])[0]
        kind=b[pos+4:pos+8].decode('ascii')
        pos+=12+length
        if pos>len(b):raise AssertionError('Truncated PNG content')
        types.append(kind)
        if kind=='IEND':break
    if types[0]!='IHDR' or types[-1]!='IEND' or any(k not in ('IHDR','IDAT','IEND') for k in types):
        raise AssertionError('Unreviewed PNG metadata chunk in '+file.name)
    return types

images=sorted((ROOT/'docs').glob('*.png'))
for f in images:png_chunks(f)
readme=(ROOT/'README.md').read_text(encoding='utf-8')
for link in re.findall(r'!\[[^]]*\]\(([^)]+)\)',readme):
    if not (ROOT/link).is_file():raise AssertionError('Broken screenshot link '+link)
print('PUBLICATION CHECK PASSED',len(text_files),'text files,',len(images),'metadata-free PNG evidence images')
