import hashlib
import itertools
import string
import time
 
 
def hash_function(algorithm, text, salt=""):
    data = (salt + text).encode()
    if algorithm == "MD5":
        return hashlib.md5(data).hexdigest()
    elif algorithm == "SHA1":
        return hashlib.sha1(data).hexdigest()
    elif algorithm == "SHA256":
        return hashlib.sha256(data).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
 
 
class CrackResult:
    def __init__(self, found, password=None, attempts=0, elapsed=0.0, method=""):
        self.found = found
        self.password = password
        self.attempts = attempts
        self.elapsed = elapsed
        self.method = method
        self.rate = attempts / elapsed if elapsed > 0 else 0
 
    def to_dict(self):
        return {
            "found": self.found,
            "password": self.password,
            "attempts": self.attempts,
            "elapsed": round(self.elapsed, 3),
            "rate": round(self.rate, 1),
            "method": self.method,
        }
 
 
class RuleMutator:
 
    LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
 
    @staticmethod
    def leet_speak(word):
        return "".join(RuleMutator.LEET_MAP.get(c.lower(), c) for c in word)
 
    @staticmethod
    def capitalize_variants(word):
        return [word.lower(), word.upper(), word.capitalize()]
 
    @staticmethod
    def append_common_suffixes(word):
        suffixes = ["1", "12", "123", "!", "2023", "2024", "2025", "01", "99"]
        return [word + s for s in suffixes]
 
    @staticmethod
    def prepend_common_prefixes(word):
        prefixes = ["1", "!", "@"]
        return [p + word for p in prefixes]
 
    @classmethod
    def generate_variants(cls, word):
        variants = set()
        variants.add(word)
 
        case_variants = cls.capitalize_variants(word)
        variants.update(case_variants)
 
        leet = cls.leet_speak(word)
        variants.add(leet)
        variants.update(cls.capitalize_variants(leet))
 
        for base in list(variants):
            variants.update(cls.append_common_suffixes(base))
 
        for base in case_variants:
            variants.update(cls.prepend_common_prefixes(base))
 
        return variants
 
 
class BruteForceCracker:
 
    def __init__(self, charset=None):
        self.charset = charset or (string.ascii_lowercase + string.digits)
 
    def crack(self, target_hash, algorithm, max_length=4, salt="", on_progress=None):
        start = time.time()
        attempts = 0
 
        for length in range(1, max_length + 1):
            for combo in itertools.product(self.charset, repeat=length):
                candidate = "".join(combo)
                attempts += 1
 
                if hash_function(algorithm, candidate, salt) == target_hash:
                    elapsed = time.time() - start
                    return CrackResult(True, candidate, attempts, elapsed, "brute_force")
 
                if on_progress and attempts % 50000 == 0:
                    on_progress(attempts, candidate)
 
        elapsed = time.time() - start
        return CrackResult(False, attempts=attempts, elapsed=elapsed, method="brute_force")
 
 
class DictionaryCracker:
 
    def __init__(self, wordlist_path, use_rules=False, max_words=None):
        self.wordlist_path = wordlist_path
        self.use_rules = use_rules
        self.max_words = max_words
 
    def _load_words(self):
        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if self.max_words and i >= self.max_words:
                        break
                    yield line.strip()
        except FileNotFoundError:
            return
 
    def crack(self, target_hash, algorithm, salt="", on_progress=None):
        start = time.time()
        attempts = 0
        method = "dictionary_with_rules" if self.use_rules else "dictionary"
 
        for word in self._load_words():
            if not word:
                continue
 
            candidates = [word]
            if self.use_rules:
                candidates = list(RuleMutator.generate_variants(word))
 
            for candidate in candidates:
                attempts += 1
                if hash_function(algorithm, candidate, salt) == target_hash:
                    elapsed = time.time() - start
                    return CrackResult(True, candidate, attempts, elapsed, method)
 
                if on_progress and attempts % 5000 == 0:
                    on_progress(attempts, candidate)
 
        elapsed = time.time() - start
        return CrackResult(False, attempts=attempts, elapsed=elapsed, method=method)
 
 
BUILTIN_WORDLIST = [
    "password", "123456", "qwerty", "letmein", "welcome", "monkey",
    "dragon", "football", "iloveyou", "admin", "summer", "winter",
    "shadow", "master", "login", "princess", "sunshine", "freedom",
    "michael", "jennifer", "computer", "internet", "trustno1",
]
 
 
def write_builtin_wordlist(path="demo_wordlist.txt"):
    with open(path, "w") as f:
        f.write("\n".join(BUILTIN_WORDLIST))
    return path
 
 
if __name__ == "__main__":
    from hasher import Hasher
 
    print("=" * 70)
    print("CRACKER TEST")
    print("=" * 70)
 
    hasher = Hasher()
    target = "summer1"
    target_hash = hasher.md5(target)["hash"]
    print(f"Target password : {target}")
    print(f"Target hash (MD5): {target_hash}\n")
 
    write_builtin_wordlist("demo_wordlist.txt")
 
    print("Dictionary attack, no rules")
    cracker = DictionaryCracker("demo_wordlist.txt", use_rules=False)
    result = cracker.crack(target_hash, "MD5")
    print(f"  Found: {result.found}  Attempts: {result.attempts}  Time: {result.elapsed:.4f}s\n")
 
    print("Dictionary attack with rule mutations")
    cracker = DictionaryCracker("demo_wordlist.txt", use_rules=True)
    result = cracker.crack(target_hash, "MD5")
    print(f"  Found: {result.found}  Password: {result.password}  "
          f"Attempts: {result.attempts}  Time: {result.elapsed:.4f}s")
 
