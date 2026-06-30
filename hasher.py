import hashlib
import os
import bcrypt
 
 
class Hasher:
 
    @staticmethod
    def md5(password):
        h = hashlib.md5(password.encode()).hexdigest()
        return {
            "algorithm": "MD5",
            "hash": h,
            "salted": False,
            "speed_class": "FAST",
            "note": "No salt, same input always gives same hash. Breakable with rainbow tables."
        }
 
    @staticmethod
    def sha1(password):
        h = hashlib.sha1(password.encode()).hexdigest()
        return {
            "algorithm": "SHA1",
            "hash": h,
            "salted": False,
            "speed_class": "FAST",
            "note": "No salt. Fast on GPUs, weak for password storage."
        }
 
    @staticmethod
    def sha256(password):
        h = hashlib.sha256(password.encode()).hexdigest()
        return {
            "algorithm": "SHA256",
            "hash": h,
            "salted": False,
            "speed_class": "FAST",
            "note": "Strong checksum, but still too fast for password storage. Billions of guesses/sec on GPU."
        }
 
    @staticmethod
    def sha256_salted(password, salt=None):
        salt = salt or os.urandom(8).hex()
        h = hashlib.sha256((salt + password).encode()).hexdigest()
        return {
            "algorithm": "SHA256+SALT",
            "hash": h,
            "salt": salt,
            "salted": True,
            "speed_class": "FAST",
            "note": "Salt makes rainbow tables useless, but the hash itself is still fast to brute force."
        }
 
    @staticmethod
    def bcrypt_hash(password, rounds=12):
        salt = bcrypt.gensalt(rounds=rounds)
        h = bcrypt.hashpw(password.encode(), salt)
        return {
            "algorithm": "BCRYPT",
            "hash": h.decode(),
            "salt": salt.decode(),
            "salted": True,
            "speed_class": "SLOW",
            "rounds": rounds,
            "note": f"Salted and slow ({rounds} rounds, 2^{rounds} iterations). This is how passwords should be stored."
        }
 
    @staticmethod
    def verify_bcrypt(password, hashed):
        return bcrypt.checkpw(password.encode(), hashed.encode())
 
 
def estimate_crack_time(algorithm, charset_size, length, guesses_per_second):
    keyspace = charset_size ** length
    seconds = keyspace / guesses_per_second if guesses_per_second > 0 else float("inf")
 
    units = [
        ("seconds", 1),
        ("minutes", 60),
        ("hours", 3600),
        ("days", 86400),
        ("years", 31536000),
        ("centuries", 3153600000),
    ]
 
    readable = f"{seconds:.2f} seconds"
    for name, divisor in units:
        if seconds / divisor < 1000:
            readable = f"{seconds/divisor:,.1f} {name}"
        else:
            continue
        break
    else:
        readable = f"{seconds/units[-1][1]:.2e} centuries"
 
    return {
        "keyspace": keyspace,
        "guesses_per_second": guesses_per_second,
        "estimated_seconds": seconds,
        "readable": readable
    }
 
 
GUESS_RATES = {
    "MD5":         10_000_000_000,
    "SHA1":         8_000_000_000,
    "SHA256":       3_000_000_000,
    "SHA256+SALT":  3_000_000_000,
    "BCRYPT":               5_000,
}
 
 
if __name__ == "__main__":
    hasher = Hasher()
    password = "Summer2024!"
 
    print("=" * 70)
    print("HASH COMPARISON")
    print("=" * 70)
    print(f"Plaintext: {password}\n")
 
    results = [
        hasher.md5(password),
        hasher.sha1(password),
        hasher.sha256(password),
        hasher.sha256_salted(password),
        hasher.bcrypt_hash(password, rounds=12),
    ]
 
    for r in results:
        print(f"{r['algorithm']:<14} {r['hash'][:50]}")
        print(f"  Salted: {r['salted']}  Speed: {r['speed_class']}")
        print(f"  {r['note']}\n")
 
    print("=" * 70)
    print("CRACK TIME ESTIMATE (8 char password, mixed case + digits + symbols)")
    print("=" * 70)
    charset = 95
    length = 8
    for algo, rate in GUESS_RATES.items():
        est = estimate_crack_time(algo, charset, length, rate)
        print(f"{algo:<14} {rate:>15,} guesses/sec  ->  worst case: {est['readable']}")
