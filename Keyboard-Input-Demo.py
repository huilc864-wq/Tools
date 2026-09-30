"""
Global Hotkey Note-Taker
------------------------
This is a PERSONAL PRODUCTIVITY TOOL, not a keylogger.

What it does:
  - Listens for ONE specific key combination: Ctrl + Alt + K
  - When you press it, it writes a timestamped line to a text file.

What it deliberately does NOT do:
  - It does not record what you type.
  - It does not run silently in the background.
  - It does not hide from the user.

The whole point is to show how a program can *notice* a keystroke
without *collecting* keystrokes.
"""

from pynput import keyboard   # pip install pynput
import datetime

# The keys we care about. Everything else is ignored.
WATCHED_KEYS = {keyboard.Key.ctrl_l, keyboard.Key.alt_l, keyboard.KeyCode.from_char('k')}

# Which keys are pressed right now?
currently_held = set()

LOG_FILE = "hotkey_notes.txt"

def write_note():
    """Append one timestamped line to the file."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{now}] Hotkey pressed.\n")
    print(f"Saved a note at {now}")

def on_press(key):
    """Called by pynput every time ANY key goes down."""
    currently_held.add(key)

    # Check if the exact combo is held down.
    if WATCHED_KEYS.issubset(currently_held):
        write_note()
        currently_held.clear()  # avoid firing repeatedly while held

def on_release(key):
    """Called by pynput every time ANY key comes up."""
    currently_held.discard(key)

    # Press Esc to quit the program cleanly.
    if key == keyboard.Key.esc:
        print("Exiting.")
        return False   # returning False stops the listener

print("Listening for Ctrl+Alt+K ... (press Esc to quit)")

# This blocks and runs the listener until it returns False.
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()