import socket  # Connect to ports on a computer.

host = input("Computer you own or have permission to scan: ").strip()  # Ask for the approved computer.
permission = input("Type YES if you have permission to scan it: ")  # Ask for clear permission.
if permission != "YES":  # Check that permission was confirmed.
    print("Scan stopped because permission was not confirmed.")  # Explain why it stopped.
    raise SystemExit  # Stop before connecting to any ports.

ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 5432, 8080]  # Check a short list of common ports.
for port in ports:  # Try each port in the list.
    try:  # Try to connect to this port.
        with socket.create_connection((host, port), timeout=0.5):  # Give the connection half a second.
            print(f"Port {port} is open")  # Show ports that accept a connection.
    except (TimeoutError, OSError):  # Handle closed ports and connection problems.
        pass  # Ignore ports that did not accept a connection.

print("Finished checking the listed ports.")  # Let the user know the scan is done.