import tkinter as tk                          # Import Tkinter for the GUI
from tkinter import filedialog                # For file selection dialog
import hashlib                               # For calculating file hashes
import os                                    # For checking if a file exists

# Function to calculate a hash (SHA1, SHA256, etc.) for a file
def calculate_hash(file_path, algo):
    hasher = hashlib.new(algo)               # Create a hash object with the selected algorithm
    with open(file_path, "rb") as f:         # Open the file in binary read mode
        for chunk in iter(lambda: f.read(4096), b""):  # Read the file in 4096 byte chunks
            hasher.update(chunk)             # Update the hash with each chunk
    return hasher.hexdigest()                # Return the final hash as a hex string

# Main function: reads user input, checks all hashes, and shows the result
def check_hash():
    file_path = file_entry.get()             # Get the file path from the GUI field
    sha1_expected = sha1_entry.get().strip().lower()      # Get expected SHA1 (if any)
    sha256_expected = sha256_entry.get().strip().lower()  # Get expected SHA256 (if any)
    sha384_expected = sha384_entry.get().strip().lower()  # Get expected SHA384 (if any)
    sha512_expected = sha512_entry.get().strip().lower()  # Get expected SHA512 (if any)

    if not os.path.isfile(file_path):        # Check if the file exists
        show_colored_message("File not found.", "red")  # Show error message
        return

    result_msg = ""                          # String for result display
    color = "green"                          # Default color is green (OK)

    # SHA1 check (if filled)
    if sha1_expected:
        sha1_actual = calculate_hash(file_path, "sha1")
        if sha1_actual == sha1_expected:
            result_msg += "✅ SHA1 matches!\n"
        else:
            result_msg += f"❌ SHA1 does not match!\nExpected: {sha1_expected}\nFound:    {sha1_actual}\n"
            color = "red"

    # SHA256 check (if filled)
    if sha256_expected:
        sha256_actual = calculate_hash(file_path, "sha256")
        if sha256_actual == sha256_expected:
            result_msg += "✅ SHA256 matches!\n"
        else:
            result_msg += f"❌ SHA256 does not match!\nExpected: {sha256_expected}\nFound:    {sha256_actual}\n"
            color = "red"

    # SHA384 check (if filled)
    if sha384_expected:
        sha384_actual = calculate_hash(file_path, "sha384")
        if sha384_actual == sha384_expected:
            result_msg += "✅ SHA384 matches!\n"
        else:
            result_msg += f"❌ SHA384 does not match!\nExpected: {sha384_expected}\nFound:    {sha384_actual}\n"
            color = "red"

    # SHA512 check (if filled)
    if sha512_expected:
        sha512_actual = calculate_hash(file_path, "sha512")
        if sha512_actual == sha512_expected:
            result_msg += "✅ SHA512 matches!\n"
        else:
            result_msg += f"❌ SHA512 does not match!\nExpected: {sha512_expected}\nFound:    {sha512_actual}\n"
            color = "red"

    show_colored_message(result_msg, color)  # Show result in popup window

# Function to open file dialog and insert selected path into GUI field
def browse_file():
    file_path = filedialog.askopenfilename()   # Open file picker dialog
    if file_path:
        file_entry.delete(0, tk.END)           # Clear previous text
        file_entry.insert(0, file_path)        # Insert selected file path

# Function to show a popup window with colored result (green/red)
def show_colored_message(msg, color):
    result_window = tk.Toplevel(root)          # Create a new popup window
    result_window.title("Result")
    result_window.geometry("650x300")
    label = tk.Label(
        result_window, text=msg, fg=color,     # Set color: green/red depending on result
        font=("Arial", 12, "bold"),
        wraplength=600, justify="left"
    )
    label.pack(pady=30, padx=20)               # Place the text in the window

# --- GUI setup (main window and input fields) ---
root = tk.Tk()
root.title("HashCheckGUI – SHA1/SHA256/SHA384/SHA512 Checker")
root.geometry("800x260")
root.resizable(False, False)

# Row 0: File picker
tk.Label(root, text="Select file:").grid(row=0, column=0, sticky="e", padx=8, pady=8)
file_entry = tk.Entry(root, width=60)
file_entry.grid(row=0, column=1, padx=5, pady=5)
tk.Button(root, text="Browse...", command=browse_file).grid(row=0, column=2, padx=5)

# Row 1: SHA1 input
tk.Label(root, text="SHA1 (optional):").grid(row=1, column=0, sticky="e", padx=8)
sha1_entry = tk.Entry(root, width=70)
sha1_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5)

# Row 2: SHA256 input
tk.Label(root, text="SHA256 (optional):").grid(row=2, column=0, sticky="e", padx=8)
sha256_entry = tk.Entry(root, width=70)
sha256_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5)

# Row 3: SHA384 input
tk.Label(root, text="SHA384 (optional):").grid(row=3, column=0, sticky="e", padx=8)
sha384_entry = tk.Entry(root, width=70)
sha384_entry.grid(row=3, column=1, columnspan=2, padx=5, pady=5)

# Row 4: SHA512 input
tk.Label(root, text="SHA512 (optional):").grid(row=4, column=0, sticky="e", padx=8)
sha512_entry = tk.Entry(root, width=70)
sha512_entry.grid(row=4, column=1, columnspan=2, padx=5, pady=5)

# Row 5: "Check hash" button
tk.Button(
    root, text="Check hash", command=check_hash,
    bg="lightgreen", font=("Arial", 12, "bold")
).grid(row=5, column=1, pady=12)

root.mainloop()                               # Start the GUI event loop
