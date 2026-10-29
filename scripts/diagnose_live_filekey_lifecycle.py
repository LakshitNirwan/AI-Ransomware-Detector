"""Safe file workload from the chat; ETW capture is not wired into this scaffold."""
from pathlib import Path
import subprocess, sys
TEST_DIR=Path(r"C:\Users\suret\AI-Ransomware-Test")
def main():
    TEST_DIR.mkdir(parents=True,exist_ok=True)
    src=TEST_DIR/"lifecycle_diagnostic.txt"; dst=TEST_DIR/"lifecycle_diagnostic.locked"
    for p in (src,dst):
        try:p.unlink()
        except FileNotFoundError:pass
    code = "from pathlib import Path\nr=Path(r'C:\\\\Users\\\\suret\\\\AI-Ransomware-Test')\ns=r/'lifecycle_diagnostic.txt'\nd=r/'lifecycle_diagnostic.locked'\ns.write_bytes(b'A'*128)\nwith s.open('rb') as f:f.read()\nwith s.open('r+b') as f:f.seek(0);f.write(b'B'*256);f.flush()\ns.rename(d)\n"
    return subprocess.run([sys.executable,"-c",code],check=False).returncode
if __name__=="__main__":
    print("Safe create/read/write/rename workload. ETW capture is not wired into this scaffold.")
    raise SystemExit(main())
