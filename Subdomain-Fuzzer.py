import socket  # Look up domain names using DNS.
import time  # Wait between lookups.

domain = input("Domain you are allowed to test, like example.com: ").strip().lower().strip(".")  # Ask for your domain.
permission = input("Type YES if you have permission to test it: ")  # Ask for clear permission.
if permission != "YES":  # Check that permission was confirmed.
    print("Lookup stopped because permission was not confirmed.")  # Explain why it stopped.
    raise SystemExit  # Stop before looking up names.

wordlist_path = input("Path to a wordlist of subdomain names: ").strip()  # Ask where the names are stored.
try:  # Try to open the wordlist.
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as wordlist:  # Read the file safely.
        names = [line.strip().lower() for line in wordlist if line.strip()]  # Keep non-empty names.
except FileNotFoundError:  # Handle a missing wordlist file.
    print("I could not find that wordlist file.")  # Tell the user what went wrong.
    raise SystemExit  # Stop because there are no names to check.

for name in names:  # Try each possible subdomain name.
    if not name.replace("-", "").isalnum():  # Skip names with unusual characters.
        continue  # Try the next name instead.
    host = f"{name}.{domain}"  # Add the name in front of your domain.
    try:  # Ask DNS whether this name exists.
        address = socket.gethostbyname(host)  # Get the matching IP address.
        print(f"Found {host} at {address}")  # Show the name and its address.
    except socket.gaierror:  # Handle a name that DNS cannot find.
        pass  # Ignore names that do not exist.
    time.sleep(0.3)  # Pause between DNS lookups.

print("Finished checking the wordlist.")  # Let the user know the lookup is done.