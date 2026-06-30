import time
from hasher import Hasher
from cracker import DictionaryCracker, BruteForceCracker, write_builtin_wordlist
from external import HashcatRunner, JohnRunner, check_tools, DEFAULT_ROCKYOU
 
 
class BenchmarkSuite:
    def __init__(self, wordlist_path=None):
        self.tools = check_tools()
        self.wordlist_path = wordlist_path or (
            DEFAULT_ROCKYOU if self.tools["rockyou"] else write_builtin_wordlist()
        )
        self.results = []
 
    def run_custom_dictionary(self, target_hash, algorithm, use_rules=False, max_words=None):
        cracker = DictionaryCracker(self.wordlist_path, use_rules=use_rules, max_words=max_words)
        result = cracker.crack(target_hash, algorithm)
        return {
            "engine": "Custom Python (rules)" if use_rules else "Custom Python",
            **result.to_dict()
        }
 
    def run_custom_bruteforce(self, target_hash, algorithm, max_length=4):
        cracker = BruteForceCracker()
        result = cracker.crack(target_hash, algorithm, max_length=max_length)
        return {"engine": "Custom Python (brute force)", **result.to_dict()}
 
    def run_hashcat(self, target_hash, algorithm, timeout=60):
        if not self.tools["hashcat"]:
            return {"engine": "hashcat", "available": False}
        runner = HashcatRunner(self.wordlist_path)
        result = runner.crack(target_hash, algorithm, timeout=timeout)
        return {"engine": "hashcat", **result}
 
    def run_john(self, target_hash, algorithm, timeout=60):
        if not self.tools["john"]:
            return {"engine": "john", "available": False}
        runner = JohnRunner(self.wordlist_path)
        result = runner.crack(target_hash, algorithm, timeout=timeout)
        return {"engine": "john", **result}
 
    def compare_all(self, password, algorithm, max_words=20000, timeout=60):
        hasher = Hasher()
        hash_fn = {
            "MD5": hasher.md5, "SHA1": hasher.sha1, "SHA256": hasher.sha256
        }.get(algorithm)
        if not hash_fn:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
 
        target_hash = hash_fn(password)["hash"]
 
        comparison = {
            "password": password,
            "algorithm": algorithm,
            "target_hash": target_hash,
            "engines": []
        }
 
        comparison["engines"].append(
            self.run_custom_dictionary(target_hash, algorithm, use_rules=False, max_words=max_words)
        )
        comparison["engines"].append(
            self.run_custom_dictionary(target_hash, algorithm, use_rules=True, max_words=max_words)
        )
        if self.tools["hashcat"]:
            comparison["engines"].append(self.run_hashcat(target_hash, algorithm, timeout=timeout))
        if self.tools["john"]:
            comparison["engines"].append(self.run_john(target_hash, algorithm, timeout=timeout))
 
        self.results.append(comparison)
        return comparison
 
    def print_comparison(self, comparison):
        print("\n" + "=" * 75)
        print(f"BENCHMARK: '{comparison['password']}'  ({comparison['algorithm']})")
        print("=" * 75)
        print(f"{'Engine':<28} {'Found':<8} {'Password':<15} {'Time(s)':<10} {'Attempts'}")
        print("-" * 75)
        for e in comparison["engines"]:
            if e.get("available") is False:
                print(f"{e['engine']:<28} {'N/A':<8} {'(not installed)':<15}")
                continue
            found = "YES" if e.get("found") else "no"
            pw = e.get("password") or "-"
            elapsed = e.get("elapsed", "-")
            attempts = e.get("attempts", "-")
            print(f"{e['engine']:<28} {found:<8} {pw:<15} {elapsed!s:<10} {attempts}")
        print("=" * 75)
 
    def salting_comparison(self, password):
        hasher = Hasher()
 
        unsalted_1 = hasher.sha256(password)["hash"]
        unsalted_2 = hasher.sha256(password)["hash"]
 
        salted_1 = hasher.sha256_salted(password)
        salted_2 = hasher.sha256_salted(password)
 
        print("\n" + "=" * 75)
        print("WHY SALTING MATTERS")
        print("=" * 75)
        print(f"Password: {password}\n")
        print(f"SHA256 (no salt) run 1 : {unsalted_1}")
        print(f"SHA256 (no salt) run 2 : {unsalted_2}")
        print(f"  identical: {unsalted_1 == unsalted_2}  (rainbow tables work against this)\n")
 
        print(f"SHA256+SALT run 1 : {salted_1['hash']}  (salt={salted_1['salt']})")
        print(f"SHA256+SALT run 2 : {salted_2['hash']}  (salt={salted_2['salt']})")
        print(f"  identical: {salted_1['hash'] == salted_2['hash']}  "
              f"(every hash is unique, rainbow tables are useless)\n")
 
        print("Timing a dictionary attack against bcrypt (slow + salted):")
        start = time.time()
        hasher.bcrypt_hash(password, rounds=12)
        hash_time = time.time() - start
        print(f"  One bcrypt hash took {hash_time:.3f}s")
        print(f"  One SHA256 hash takes roughly 0.000001s")
        print(f"  That difference, multiplied across a 14 million word list, "
              f"is the entire point of slow hashing.")
        print("=" * 75)
 
 
if __name__ == "__main__":
    suite = BenchmarkSuite()
 
    print("Tools detected:", suite.tools)
    print(f"Using wordlist: {suite.wordlist_path}\n")
 
    comparison = suite.compare_all("password1", "MD5", max_words=20000, timeout=30)
    suite.print_comparison(comparison)
 
    suite.salting_comparison("Summer2024!")
 
