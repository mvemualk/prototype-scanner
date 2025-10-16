#!/usr/bin/env python3
"""
zip_scanner.py
Simple ZIP analyzer prototype for MVP.
Usage: python zip_scanner.py /path/to/uploaded.zip /path/to/output.json
"""

import sys, os, zipfile, tempfile, hashlib, json, re, shutil, stat, argparse

BASE64_RE = re.compile(rb'(?:[A-Za-z0-9+/]{100,}={0,2})')  # long base64 chunks
SUSPICIOUS_EXT = {'.exe', '.dll', '.bin', '.so', '.scr', '.com', '.pif'}
SCRIPT_EXT = {'.js', '.py', '.sh', '.ps1', '.rb'}

def sha256_of_file(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def scan_extracted(root):
    findings = []
    file_list = []
    hashes = {}
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            rel = os.path.relpath(fp, root)
            file_list.append(rel)
            try:
                h = sha256_of_file(fp)
                hashes[rel] = h
            except Exception as e:
                hashes[rel] = f"err:{e}"

            ext = os.path.splitext(fn)[1].lower()
            # suspicious extension
            if ext in SUSPICIOUS_EXT:
                findings.append({
                    "severity":"high","title":"Native binary found",
                    "description":f"Native executable or library: {rel}",
                    "evidence":[rel]
                })
            # scripts: inspect for base64 or suspicious calls
            if ext in SCRIPT_EXT or ext=='':
                try:
                    with open(fp,'rb') as fh:
                        data = fh.read()
                    # base64 chunk detection
                    if BASE64_RE.search(data):
                        findings.append({
                            "severity":"medium",
                            "title":"Base64-like blob",
                            "description":f"Large base64-like block found in {rel}",
                            "evidence":[rel]
                        })
                    # suspicious patterns (eval, exec, powershell download)
                    text = None
                    try:
                        text = data.decode('utf-8', errors='ignore').lower()
                    except:
                        text = ''
                    if 'eval(' in text or 'exec(' in text or 'require("child_process")' in text or 'powershell' in text:
                        findings.append({
                            "severity":"medium",
                            "title":"Potential code execution pattern",
                            "description":f"Strings like eval/exec/child_process/powershell in {rel}",
                            "evidence":[rel]
                        })
                except Exception as e:
                    findings.append({"severity":"low","title":"File read error","description":str(e),"evidence":[rel]})

    return file_list, hashes, findings

def main(inzip, outjson):
    if not zipfile.is_zipfile(inzip):
        print("Not a zip file", file=sys.stderr); sys.exit(2)

    tmp = tempfile.mkdtemp(prefix="zipscan_")
    try:
        with zipfile.ZipFile(inzip,'r') as z:
            z.extractall(tmp)
        file_list, hashes, findings = scan_extracted(tmp)
        score = max(0, 100 - 10*sum(1 for f in findings if f['severity']=='high'))
        report = {
            "job_id": os.path.basename(inzip) + "_" + hashlib.sha256(open(inzip,'rb').read()).hexdigest()[:8],
            "status":"complete",
            "summary":{"score":score, "verdict": "suspicious" if any(f['severity'] in ('high','medium') for f in findings) else "clean"},
            "findings": findings,
            "artifacts":{"file_list":file_list, "hashes":hashes},
            "created_at": __import__('datetime').datetime.utcnow().isoformat()+'Z'
        }
        with open(outjson,'w') as fo:
            json.dump(report, fo, indent=2)
        print("Report written to", outjson)
    finally:
        shutil.rmtree(tmp)

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument("zipfile")
    p.add_argument("outjson")
    args=p.parse_args()
    main(args.zipfile, args.outjson)
