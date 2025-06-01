import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import hashlib
import os
import gnupg
import tempfile

# ----- DISTRO KEYS -----
LINUX_KEYS = {
    "Ubuntu":      "0x46181433FBB75451",
    "Linux Mint":  "0x27DEB15644C6B3CF3EE8A145B7F2239E98BC6BFC",
    "Debian":      "0xA1BD8E9956E7C94E",
    "Fedora":      "0x2F86D6A1",
    "Arch Linux":  "0x9741E8AC",
    "Kali Linux":  "0x44C6B3CF",
    "elementary":  "0xC842FAE4A27F1F1B",
    "Manjaro":     "0xC847B2A220C4E2D6",
    "Tails":       "0xBDD7BDBB7B7893ED",
    "Qubes":       "0x184B0146B739A8A7",
    "Pop!_OS":     "0xE4C912C2",
    "Zorin":       "0xF6ECB3762474EDA9",
    "OpenSUSE":    "0x307E3D54",
    "Other (manual entry)": "",
}
DEFAULT_KEYSERVER = "keyserver.ubuntu.com"

# ----- HASHCHECK FUNKTIONER -----
def calculate_hash(file_path, algo):
    hasher = hashlib.new(algo)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def check_hash():
    file_path = file_entry.get()
    sha1_expected = sha1_entry.get().strip().lower()
    sha256_expected = sha256_entry.get().strip().lower()
    sha384_expected = sha384_entry.get().strip().lower()
    sha512_expected = sha512_entry.get().strip().lower()

    if not os.path.isfile(file_path):
        show_colored_message("File not found.", "red")
        return

    result_msg = ""
    color = "green"

    # SHA1
    if sha1_expected:
        possible_hashes = []
        for v in sha1_expected.replace(",", " ").split():
            v = v.strip()
            if v:
                possible_hashes.append(v)
        sha1_actual = calculate_hash(file_path, "sha1")
        matches = [h for h in possible_hashes if sha1_actual == h]
        if matches:
            result_msg += f"✅ SHA1 matches the following value(s):\n"
            for h in matches:
                result_msg += f"  {h}\n"
        else:
            result_msg += "❌ SHA1 does not match!\nExpected one of:\n"
            for h in possible_hashes:
                result_msg += f"  {h}\n"
            result_msg += f"Found:    {sha1_actual}\n"
            color = "red"

    # SHA256
    if sha256_expected:
        possible_hashes = []
        for v in sha256_expected.replace(",", " ").split():
            v = v.strip()
            if v:
                possible_hashes.append(v)
        sha256_actual = calculate_hash(file_path, "sha256")
        matches = [h for h in possible_hashes if sha256_actual == h]
        if matches:
            result_msg += f"✅ SHA256 matches the following value(s):\n"
            for h in matches:
                result_msg += f"  {h}\n"
        else:
            result_msg += "❌ SHA256 does not match!\nExpected one of:\n"
            for h in possible_hashes:
                result_msg += f"  {h}\n"
            result_msg += f"Found:    {sha256_actual}\n"
            color = "red"

    # SHA384
    if sha384_expected:
        possible_hashes = []
        for v in sha384_expected.replace(",", " ").split():
            v = v.strip()
            if v:
                possible_hashes.append(v)
        sha384_actual = calculate_hash(file_path, "sha384")
        matches = [h for h in possible_hashes if sha384_actual == h]
        if matches:
            result_msg += f"✅ SHA384 matches the following value(s):\n"
            for h in matches:
                result_msg += f"  {h}\n"
        else:
            result_msg += "❌ SHA384 does not match!\nExpected one of:\n"
            for h in possible_hashes:
                result_msg += f"  {h}\n"
            result_msg += f"Found:    {sha384_actual}\n"
            color = "red"

    # SHA512
    if sha512_expected:
        possible_hashes = []
        for v in sha512_expected.replace(",", " ").split():
            v = v.strip()
            if v:
                possible_hashes.append(v)
        sha512_actual = calculate_hash(file_path, "sha512")
        matches = [h for h in possible_hashes if sha512_actual == h]
        if matches:
            result_msg += f"✅ SHA512 matches the following value(s):\n"
            for h in matches:
                result_msg += f"  {h}\n"
        else:
            result_msg += "❌ SHA512 does not match!\nExpected one of:\n"
            for h in possible_hashes:
                result_msg += f"  {h}\n"
            result_msg += f"Found:    {sha512_actual}\n"
            color = "red"

    show_colored_message(result_msg, color)

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def show_colored_message(msg, color):
    result_window = tk.Toplevel(root)
    result_window.title("Result")
    result_window.geometry("650x300")
    label = tk.Label(
        result_window, text=msg, fg=color,
        font=("Arial", 12, "bold"),
        wraplength=600, justify="left"
    )
    label.pack(pady=30, padx=20)

def parse_hashlist_for_filename(hashlist_str, target_filename):
    found = False
    hash_value = ""
    for line in hashlist_str.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith(target_filename):
            hash_value = line.split()[0].lower()
            found = True
            break
    return hash_value if found else None

def load_hash_file_generic():
    hash_file = filedialog.askopenfilename(
        title="Select hash list (any text file)",
        filetypes=[("Text files", "*.txt *.sha1 *.sha256 *.sha512 *.hash *SUMS*"), ("All files", "*.*")]
    )
    if not hash_file:
        return
    target_filename = os.path.basename(file_entry.get())
    if not target_filename:
        show_colored_message("Select the file you want to check first!", "red")
        return
    with open(hash_file, "r", encoding="utf-8", errors="ignore") as f:
        hashlist_str = f.read()
        hash_value = parse_hashlist_for_filename(hashlist_str, target_filename)
        if hash_value:
            sha256_entry.delete(0, tk.END)
            sha256_entry.insert(0, hash_value)
            show_colored_message(f"Found hash for {target_filename}:\n{hash_value}", "green")
        else:
            show_colored_message(f"No hash found in list for {target_filename}", "red")

def load_sha256sums_file():
    hash_file = filedialog.askopenfilename(
        title="Select SHA256SUMS.txt",
        filetypes=[("SHA256SUMS Files", "*SHA256SUMS*"), ("Text files", "*.txt"), ("All files", "*.*")]
    )
    if not hash_file:
        return
    target_filename = os.path.basename(file_entry.get())
    if not target_filename:
        show_colored_message("Select the file you want to check first!", "red")
        return
    with open(hash_file, "r", encoding="utf-8", errors="ignore") as f:
        hashlist_str = f.read()
        hash_value = parse_hashlist_for_filename(hashlist_str, target_filename)
        if hash_value:
            sha256_entry.delete(0, tk.END)
            sha256_entry.insert(0, hash_value)
            show_colored_message(f"Found hash for {target_filename}:\n{hash_value}", "green")
        else:
            show_colored_message(f"No hash found in list for {target_filename}", "red")

def load_sha256sums_text():
    target_filename = os.path.basename(file_entry.get())
    if not target_filename:
        show_colored_message("Select the file you want to check first!", "red")
        return
    hashlist_str = hashlist_text.get("1.0", tk.END)
    if not hashlist_str.strip():
        show_colored_message("Paste SHA*SUMS content above first!", "red")
        return
    hash_value = parse_hashlist_for_filename(hashlist_str, target_filename)
    if hash_value:
        sha256_entry.delete(0, tk.END)
        sha256_entry.insert(0, hash_value)
        show_colored_message(f"Found hash for {target_filename}:\n{hash_value}", "green")
    else:
        show_colored_message(f"No hash found in list for {target_filename}", "red")

# ----- GPG SIGNATURE CHECK -----
def browse_sha256sums():
    filename = filedialog.askopenfilename(title="Select SHA256SUMS file", filetypes=[("SHA256SUMS", "*SHA256SUMS*"), ("All files", "*.*")])
    if filename:
        sha256sums_path.set(filename)

def browse_sha256sums_gpg():
    filename = filedialog.askopenfilename(title="Select SHA256SUMS.gpg file", filetypes=[("SHA256SUMS.gpg", "*SHA256SUMS.gpg*"), ("All files", "*.*")])
    if filename:
        sha256sums_gpg_path.set(filename)

def verify_signature():
    distro = distro_var.get()
    key_id = key_entry.get().strip()
    if not key_id:
        key_id = LINUX_KEYS[distro]
    if not key_id:
        gpg_status_label.config(text="Please enter a Key ID.", fg="red")
        return

    sums = sha256sums_path.get()
    sums_gpg = sha256sums_gpg_path.get()

    # NYT: Håndter copy-paste SHA256SUMS.gpg
    gpgsig_text_content = gpgsig_text.get("1.0", tk.END).strip()
    temp_sig_file = None
    if not sums_gpg and gpgsig_text_content:
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix=".gpg")
        temp_file.write(gpgsig_text_content)
        temp_file.close()
        sums_gpg = temp_file.name
        temp_sig_file = temp_file.name

    if not (os.path.isfile(sums) and os.path.isfile(sums_gpg)):
        gpg_status_label.config(text="Please select SHA256SUMS and SHA256SUMS.gpg (or paste signature above).", fg="red")
        if temp_sig_file:
            os.unlink(temp_sig_file)
        return

    gpg_status_label.config(text="Fetching public key...", fg="blue")
    gpg = gnupg.GPG()
    result = gpg.recv_keys(DEFAULT_KEYSERVER, key_id)
    if "imported" not in result.summary() and "unchanged" not in result.summary():

        gpg_status_label.config(text=f"Failed to import key {key_id} from keyserver.", fg="red")
        if temp_sig_file:
            os.unlink(temp_sig_file)
        return

    gpg_status_label.config(text="Verifying signature...", fg="blue")
    with open(sums_gpg, "rb") as sig, open(sums, "rb") as content:
        verified = gpg.verify_file(sig, sums)
        if verified and verified.valid:
            text = f"✔ Signature VERIFIED!\nSigned by: {verified.username}\nKey ID: {verified.key_id}"
            gpg_status_label.config(text=text, fg="green")
        else:
            text = f"❌ Signature NOT valid!\nStatus: {verified.status}\nKey ID: {key_id}"
            gpg_status_label.config(text=text, fg="red")

    if temp_sig_file:
        os.unlink(temp_sig_file)

# -------- GUI SETUP --------
root = tk.Tk()
root.title("HashCheckGUI + GPG Signature Verifier")
root.geometry("980x780")
root.resizable(False, False)

# Hash checker GUI (øverst)
tk.Label(root, text="Select file:").grid(row=0, column=0, sticky="e", padx=8, pady=8)
file_entry = tk.Entry(root, width=60)
file_entry.grid(row=0, column=1, padx=5, pady=5)
tk.Button(root, text="Browse...", command=browse_file).grid(row=0, column=2, padx=5)

tk.Label(root, text="SHA1 (optional):").grid(row=1, column=0, sticky="e", padx=8)
sha1_entry = tk.Entry(root, width=80)
sha1_entry.grid(row=1, column=1, columnspan=4, padx=5, pady=5)

tk.Label(root, text="SHA256 (optional):").grid(row=2, column=0, sticky="e", padx=8)
sha256_entry = tk.Entry(root, width=80)
sha256_entry.grid(row=2, column=1, columnspan=4, padx=5, pady=5)

tk.Label(root, text="SHA384 (optional):").grid(row=3, column=0, sticky="e", padx=8)
sha384_entry = tk.Entry(root, width=80)
sha384_entry.grid(row=3, column=1, columnspan=4, padx=5, pady=5)

tk.Label(root, text="SHA512 (optional):").grid(row=4, column=0, sticky="e", padx=8)
sha512_entry = tk.Entry(root, width=80)
sha512_entry.grid(row=4, column=1, columnspan=4, padx=5, pady=5)

tk.Label(root, text="Paste SHA*SUMS text (optional):").grid(row=5, column=0, sticky="ne", padx=8, pady=8)
hashlist_text = scrolledtext.ScrolledText(root, width=80, height=7)
hashlist_text.grid(row=5, column=1, columnspan=4, padx=5, pady=8)

button_frame = tk.Frame(root)
button_frame.grid(row=6, column=1, columnspan=4, pady=(10, 0), sticky="w")

btn1 = tk.Button(button_frame, text="Load SHA256SUMS.txt", command=load_sha256sums_file, bg="#add8e6")
btn2 = tk.Button(button_frame, text="Load any hash file", command=load_hash_file_generic, bg="#bfe6bf")
btn3 = tk.Button(button_frame, text="Parse hash from pasted text", command=load_sha256sums_text, bg="#add8e6")
btn1.pack(side="left", padx=4)
btn2.pack(side="left", padx=4)
btn3.pack(side="left", padx=4)

tk.Button(
    root, text="Check hash", command=check_hash,
    bg="lightgreen", font=("Arial", 12, "bold")
).grid(row=7, column=3, columnspan=2, pady=18, sticky="e")

# --- GPG signature checker sektion (nederst) ---
tk.Label(root, text="--- SHA256SUMS Signature Verification ---", font=("Arial", 12, "bold")).grid(row=8, column=0, columnspan=5, pady=(20,0))

tk.Label(root, text="Select distribution:").grid(row=9, column=0, sticky="e", padx=8, pady=8)
distro_var = tk.StringVar()
distro_var.set("Ubuntu")
distro_menu = ttk.Combobox(root, textvariable=distro_var, values=list(LINUX_KEYS.keys()), state="readonly", width=30)
distro_menu.grid(row=9, column=1, padx=5, pady=8, sticky="w")

tk.Label(root, text="Key ID (manual, optional):").grid(row=10, column=0, sticky="e", padx=8, pady=2)
key_entry = tk.Entry(root, width=35)
key_entry.grid(row=10, column=1, padx=5, sticky="w")

tk.Label(root, text="SHA256SUMS file:").grid(row=11, column=0, sticky="e", padx=8, pady=2)
sha256sums_path = tk.StringVar()
tk.Entry(root, textvariable=sha256sums_path, width=38).grid(row=11, column=1, padx=5, sticky="w")
tk.Button(root, text="Browse...", command=browse_sha256sums).grid(row=11, column=2, padx=5)

tk.Label(root, text="SHA256SUMS.gpg file:").grid(row=12, column=0, sticky="e", padx=8, pady=2)
sha256sums_gpg_path = tk.StringVar()
tk.Entry(root, textvariable=sha256sums_gpg_path, width=38).grid(row=12, column=1, padx=5, sticky="w")
tk.Button(root, text="Browse...", command=browse_sha256sums_gpg).grid(row=12, column=2, padx=5)

tk.Label(root, text="Paste SHA256SUMS.gpg (optional):").grid(row=13, column=0, sticky="ne", padx=8, pady=2)
gpgsig_text = scrolledtext.ScrolledText(root, width=38, height=4)
gpgsig_text.grid(row=13, column=1, columnspan=2, padx=5, pady=4)

tk.Button(root, text="Verify signature", command=verify_signature, bg="#aaffaa", font=("Arial", 12, "bold")).grid(row=14, column=1, pady=20)
gpg_status_label = tk.Label(root, text="", font=("Arial", 11, "bold"))
gpg_status_label.grid(row=15, column=0, columnspan=3, padx=5, pady=5)

root.mainloop()
