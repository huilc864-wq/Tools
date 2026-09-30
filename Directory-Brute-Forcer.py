import time  # Wait between requests so the scan stays slow.
from urllib.error import HTTPError, URLError  # Read common website errors.
from urllib.parse import quote  # Make each path safe to place in a URL.
from urllib.request import Request, urlopen  # Send website requests without extra packages.

target = input("Website URL you are allowed to test: ").strip().rstrip("/")  # Ask for your own test website.
if not target.startswith(("http://", "https://")):  # Check that the address starts correctly.
	print("Please enter a URL that starts with http:// or https://.")  # Explain the problem.
	raise SystemExit  # Stop because the address is not usable.

permission = input("Type YES if you have permission to test it: ")  # Ask for clear permission.
if permission != "YES":  # Check that permission was confirmed.
	print("Scan stopped because permission was not confirmed.")  # Explain why it stopped.
	raise SystemExit  # Stop before sending any requests.

wordlist_path = input("Path to your wordlist file: ").strip()  # Ask where the paths are stored.
try:  # Try to open the wordlist.
	with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as wordlist:  # Read the file safely.
		paths = [line.strip() for line in wordlist if line.strip()]  # Keep only non-empty lines.
except FileNotFoundError:  # Handle a missing wordlist file.
	print("I could not find that wordlist file.")  # Tell the user what went wrong.
	raise SystemExit  # Stop because there are no paths to test.

for path in paths:  # Try each path from the wordlist.
	url = f"{target}/{quote(path.strip('/'), safe='/')}"  # Join the website and path safely.
	request = Request(url, headers={"User-Agent": "Simple-Authorized-Test/1.0"})  # Identify this script.
	try:  # Try to open this one address.
		with urlopen(request, timeout=4) as response:  # Wait no longer than four seconds.
			status = response.status  # Remember the website's status code.
	except HTTPError as error:  # Keep status codes such as 403 and 404.
		status = error.code  # Save the error's status code.
	except URLError as error:  # Handle a connection problem.
		print(f"Could not reach {url}: {error.reason}")  # Show the connection problem.
		time.sleep(0.5)  # Pause before trying the next path.
		continue  # Move on to the next path.
	if status in (200, 301, 302, 401, 403):  # Show responses that may be worth checking.
		print(f"{status}  {url}")  # Print the status and address.
	time.sleep(0.5)  # Pause between requests.

print("Finished checking the wordlist.")  # Let the user know the scan is done.
