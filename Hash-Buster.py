import hashlib  # Hash algorithms-এর জন্য।
import hmac  # Hash safely compare করার জন্য।
import os  # File check করার জন্য।

ALGORITHMS = {  # Supported common algorithms।
    "md5": hashlib.md5, "sha1": hashlib.sha1,
    "sha224": hashlib.sha224, "sha256": hashlib.sha256,
    "sha384": hashlib.sha384, "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256, "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b, "blake2s": hashlib.blake2s
}

def make_hash(data, algorithm):  # Text থেকে hash বানাবে।
    return ALGORITHMS[algorithm](data.encode()).hexdigest()  # Hash return করবে।

def file_hash(path, algorithm):  # File-এর hash বানাবে।
    h = ALGORITHMS[algorithm]()  # Hash object তৈরি করবে।
    with open(path, "rb") as f:  # File binary mode-এ খুলবে।
        for chunk in iter(lambda: f.read(1024 * 1024), b""):  # 1 MB করে পড়বে।
            h.update(chunk)  # Data hash-এ যোগ করবে।
    return h.hexdigest()  # Final hash return করবে।

def detect(value):  # Hash length দেখে সম্ভাব্য algorithm দেখাবে।
    lengths = {32:"MD5", 40:"SHA-1", 56:"SHA-224", 64:"SHA-256/SHA3-256/BLAKE2s", 96:"SHA-384/SHA3-384", 128:"SHA-512/SHA3-512/BLAKE2b"}  # Common lengths।
    return lengths.get(len(value.strip()), "Unknown")  # Result return করবে।

print("=" * 45)  # Header।
print("SMART HASH AUDITOR")  # Tool name।
print("=" * 45)  # Header।
print("1. Hash text")  # Text option।
print("2. Hash file")  # File option।
print("3. Verify hash")  # Verify option।
print("4. Detect hash")  # Detect option।
choice = input("Choose: ").strip()  # User choice নেবে।

if choice == "1":  # Text hashing।
    text = input("Text: ")  # Text নেবে।
    alg = input("Algorithm: ").lower().strip()  # Algorithm নেবে।
    if alg in ALGORITHMS:  # Algorithm valid হলে।
        print(make_hash(text, alg))  # Hash দেখাবে।
    else: print("Unsupported algorithm.")  # Invalid algorithm।

elif choice == "2":  # File hashing।
    path = input("File: ").strip()  # File path নেবে।
    alg = input("Algorithm: ").lower().strip()  # Algorithm নেবে।
    if os.path.isfile(path) and alg in ALGORITHMS:  # File ও algorithm valid হলে।
        print(file_hash(path, alg))  # File hash দেখাবে।
    else: print("Invalid file or algorithm.")  # Error দেখাবে।

elif choice == "3":  # Hash verification।
    text = input("Text: ")  # Candidate text নেবে।
    expected = input("Known hash: ").strip().lower()  # Known hash নেবে।
    alg = input("Algorithm: ").lower().strip()  # Algorithm নেবে।
    if alg in ALGORITHMS:  # Algorithm valid হলে।
        actual = make_hash(text, alg)  # Candidate-এর hash বানাবে।
        print("MATCH" if hmac.compare_digest(actual, expected) else "NO MATCH")  # Compare করবে।
    else: print("Unsupported algorithm.")  # Invalid algorithm।

elif choice == "4":  # Hash detection।
    value = input("Hash: ").strip()  # Hash নেবে।
    print("Possible type:", detect(value))  # সম্ভাব্য type দেখাবে।

else:  # ভুল option।
    print("Invalid choice.")  # Error দেখাবে।