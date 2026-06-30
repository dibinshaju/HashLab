# HashLab

HashLab lets developers generate passwords, hash them (MD5–bcrypt), and instantly test them against real cracking engines (custom, hashcat, john) using wordlists like rockyou.txt. Unlike separate hash/strength tools, it shows actual crack time — if it falls instantly, it's weak. Fix and retest on the same platform.

## Why this exists

Most password workflows split testing across separate tools — one lab generates a hash, another scores "strength" based on rules like length or character variety, but neither actually tests the password against real-world cracking data. HashLab closes that gap by generating a password and hash together, then immediately attacking that same hash with real cracking engines and industry-standard wordlists, so the result is a measured outcome instead of a guess.

## Getting Started (GUI)

The GUI is the main way to use HashLab — a four-tab PyQt5 interface that wires directly into the underlying engine, so you can generate, crack, and benchmark without touching the command line.

### Requirements

```bash
pip install PyQt5 bcrypt
```

Optional, for full benchmarking against industry tools:
- [hashcat](https://hashcat.net/hashcat/)
- [john the ripper](https://www.openwall.com/john/)
- a wordlist such as `rockyou.txt` (commonly found at `/usr/share/wordlists/rockyou.txt` on Kali)

HashLab automatically detects which of these are installed and skips any that aren't, so it still runs fine with just the built-in Python engine.

### Launch

```bash
python3 gui.py
```

A window opens with four tabs:

**1. Hash Generator**
Enter a plaintext password and pick a method (MD5, SHA1, SHA256, salted SHA256, or bcrypt) to see the resulting hash instantly.

**2. Crack**
Paste a target hash (or use one generated in tab 1), select the algorithm it was hashed with, and choose an engine: the built-in dictionary/rule/brute-force cracker, or external hashcat/john if installed. Cracking runs on a background thread, so the window stays responsive while it works.

**3. Benchmark**
Runs the same target hash through every available engine back to back and displays a comparison table: which engines found it, the password if recovered, time taken, and attempts made. Quick gut-check on how a password actually holds up across tools.

**4. Why Salting Matters**
A live side-by-side demo: hashes the same password twice with plain SHA256 (showing identical output every time) versus salted SHA256 (showing different output every time), then times one bcrypt hash against one SHA256 hash to make the cost difference concrete.

### Reading the results

- **Found instantly / low attempt count** → the password is weak under that hashing method; don't ship it as-is.
- **Not found within timeout** → the password+method combination held up against that engine's attack.
- Compare the same password across hashing methods (e.g. raw SHA256 vs bcrypt) to see how much the *method* matters independent of password choice — that's the core lesson HashLab is built to demonstrate.

## Command-line use

Each module can also be used independently if you'd rather script things:

```python
from hasher import Hasher
from cracker import DictionaryCracker
```

See individual files (`hasher.py`, `cracker.py`, `external.py`, `benchmark.py`) for class-level details.

## Disclaimer

This tool is built for education and legitimate security testing — auditing your own systems, learning how password hashing works, or demonstrating these concepts to others. Only test hashes and passwords you own or have explicit permission to test. Misuse against systems or accounts you don't control is illegal.

## Author

Built by [dibinshaju](https://github.com/dibinshaju), part of ongoing cybersecurity learning and tooling work within the Kerala security community.
