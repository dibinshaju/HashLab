import subprocess
import shutil
import os
import tempfile
import time
 
 
HASHCAT_MODES = {
    "MD5": "0",
    "SHA1": "100",
    "SHA256": "1400",
    "SHA256+SALT": "1410",
    "BCRYPT": "3200",
}
 
JOHN_FORMATS = {
    "MD5": "raw-md5",
    "SHA1": "raw-sha1",
    "SHA256": "raw-sha256",
    "BCRYPT": "bcrypt",
}
 
DEFAULT_ROCKYOU = "/usr/share/wordlists/rockyou.txt"
 
 
def tool_available(name):
    return shutil.which(name) is not None
 
 
def check_tools():
    return {
        "hashcat": tool_available("hashcat"),
        "john": tool_available("john"),
        "rockyou": os.path.exists(DEFAULT_ROCKYOU),
    }
 
 
class HashcatRunner:
 
    def __init__(self, wordlist_path=DEFAULT_ROCKYOU):
        self.wordlist_path = wordlist_path
 
    def crack(self, target_hash, algorithm, timeout=60):
        if not tool_available("hashcat"):
            return {"available": False, "error": "hashcat not installed"}
 
        mode = HASHCAT_MODES.get(algorithm)
        if mode is None:
            return {"available": True, "found": False,
                     "error": f"No hashcat mode mapped for {algorithm}"}
 
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as f:
            f.write(target_hash + "\n")
            hash_file = f.name
 
        cmd = [
            "hashcat", "-m", mode, "-a", "0",
            hash_file, self.wordlist_path,
            "--potfile-disable", "--quiet"
        ]
 
        start = time.time()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            os.unlink(hash_file)
            return {
                "available": True, "found": False,
                "command": " ".join(cmd),
                "elapsed": timeout,
                "error": f"Timed out after {timeout}s"
            }
        except FileNotFoundError:
            os.unlink(hash_file)
            return {"available": False, "error": "hashcat binary not found"}
 
        elapsed = time.time() - start
        os.unlink(hash_file)
 
        output = result.stdout + result.stderr
        found = ":" in output and target_hash.lower() in output.lower()
        password = None
        if found:
            for line in output.splitlines():
                if target_hash.lower() in line.lower():
                    parts = line.strip().split(":")
                    if len(parts) >= 2:
                        password = parts[-1]
                    break
 
        return {
            "available": True,
            "found": found,
            "password": password,
            "elapsed": round(elapsed, 3),
            "command": " ".join(cmd),
            "raw_output": output[-500:],
        }
 
 
class JohnRunner:
 
    def __init__(self, wordlist_path=DEFAULT_ROCKYOU):
        self.wordlist_path = wordlist_path
 
    def crack(self, target_hash, algorithm, timeout=60):
        if not tool_available("john"):
            return {"available": False, "error": "john not installed"}
 
        fmt = JOHN_FORMATS.get(algorithm)
        if fmt is None:
            return {"available": True, "found": False,
                     "error": f"No john format mapped for {algorithm}"}
 
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as f:
            f.write(f"target:{target_hash}\n")
            hash_file = f.name
 
        cmd = ["john", f"--format={fmt}", f"--wordlist={self.wordlist_path}", hash_file]
 
        start = time.time()
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            os.unlink(hash_file)
            return {"available": False, "error": "john binary not found"}
 
        elapsed = time.time() - start
 
        show_cmd = ["john", f"--format={fmt}", "--show", hash_file]
        show_result = subprocess.run(show_cmd, capture_output=True, text=True)
        output = show_result.stdout
 
        found = "target:" in output
        password = None
        if found:
            for line in output.splitlines():
                if line.startswith("target:"):
                    password = line.split(":", 1)[1].split(":")[0]
                    break
 
        os.unlink(hash_file)
 
        return {
            "available": True,
            "found": found,
            "password": password,
            "elapsed": round(elapsed, 3),
            "command": " ".join(cmd),
            "raw_output": output[-500:],
        }
 
 
if __name__ == "__main__":
    print("Checking installed tools...")
    status = check_tools()
    for tool, ok in status.items():
        print(f"  {tool:<10} {'FOUND' if ok else 'NOT FOUND'}")
 
    if not status["hashcat"] and not status["john"]:
        print("\nNeither hashcat nor john found. Install with:")
        print("  sudo apt install hashcat john")
        exit()
 
    from hasher import Hasher
    hasher = Hasher()
    target = "password1"
    target_hash = hasher.md5(target)["hash"]
    print(f"\nTarget password : {target}")
    print(f"Target hash     : {target_hash}\n")
 
    if status["hashcat"]:
        print("Running hashcat...")
        runner = HashcatRunner()
        result = runner.crack(target_hash, "MD5", timeout=30)
        print(f"  Found: {result.get('found')}  Password: {result.get('password')}  "
              f"Time: {result.get('elapsed')}s")
 
    if status["john"]:
        print("\nRunning john...")
        runner = JohnRunner()
        result = runner.crack(target_hash, "MD5", timeout=30)
        print(f"  Found: {result.get('found')}  Password: {result.get('password')}  "
              f"Time: {result.get('elapsed')}s")
 
