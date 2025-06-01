# HashCheckGUI – Easy Hash & GPG Signature Verifier

**Latest release:** [v1.1.0](https://github.com/[your-username]/[your-repo]/releases/tag/v1.1.0)  
*See the Releases page for the latest .exe downloads and changelogs!*

## What is this?

HashCheckGUI makes it easy and secure to verify your Linux ISOs and other downloads:
- **Check file hashes (SHA1, SHA256, SHA384, SHA512)**
- **Auto-extract hash from pasted SHA*SUMS lists**
- **Full GPG signature verification for SHA256SUMS files from major Linux distros**
- **Paste .gpg signature directly – no need to save as a file!**

---

## Features

- **Simple hash check:**  
  Paste or load hashes (SHA1/SHA256/SHA384/SHA512) and verify any file.
- **Hash-list parsing:**  
  Paste the whole SHA*SUMS list, and HashCheckGUI finds the correct hash for your file.
- **Works with all standard hash file formats** (txt, SUMS, hash, etc.).
- **GPG signature verification:**  
  - Fetches public key for your distro automatically.
  - Works with both signature files and copy-pasted signature text.
  - Shows signed key name and key ID for full authenticity check.
- **Supports all major Linux distributions**
- **User-friendly, color-coded results.**

---

## Why use this?

- Hashes ensure the file is not corrupted or modified.
- GPG signatures on the hash list guarantee the list itself is official – so you’re protected against tampering at every step.

---

## How to use

### 1. Check file hash
- Select your ISO or file.
- Paste or load the hash (SHA256 etc.), OR paste the entire SHA*SUMS list and click "Parse hash from pasted text".
- Click "Check hash".

### 2. Verify SHA256SUMS signature (if your distro provides GPG)
- Download (or copy) SHA256SUMS (the hash list) and select as "SHA256SUMS file".
- Download or copy SHA256SUMS.gpg (the signature) and select or paste as text.
- Choose your distribution (or enter a key ID manually).
- Click "Verify signature".

---

## Supported distributions

- **GPG signature + hash:** Ubuntu, Linux Mint, Debian, Fedora, Arch, Kali, Manjaro, Tails, Qubes, Zorin, elementary, OpenSUSE (and more).
- **Hash-only (no GPG):** Pop!_OS and some others only provide SHA256 hashes. In this case, just check the hash – you cannot verify the hash list itself.

---

## Requirements

- Python 3.8+
- `python-gnupg`, `tkinter`
- GnuPG (gpg) installed and in your PATH for signature checking

---

## Changelog

### v1.1.0
- **Added:** GPG signature verification for SHA256SUMS files
- **Added:** Paste .gpg signature directly (no need to save file)
- **Improved:** Better error handling and user instructions
- **Improved:** Updated distro/key database and README

---

## License

MIT License  
Created by [your username]

---

## Feedback & Contributions

Open an issue or PR if you find bugs, have ideas, or want to improve HashCheckGUI.  
This tool is for everyone who wants *easy, secure, offline* verification!

