# HashCheckGUI – Easy Hash & GPG Signature Verifier

This is an easy-to-use graphical tool for verifying the **integrity** and **authenticity** of Linux ISO downloads – or any file you want to check.  
It supports SHA1, SHA256, SHA384, SHA512 hash checking and full **GPG signature verification** of SHA256SUMS files from all major Linux distributions.

## Features

- **Check file integrity:**  
  Enter or load SHA1, SHA256, SHA384, or SHA512 hash values and verify any file.
- **Auto-extract hash:**  
  Paste a full SHA*SUMS list (e.g., from a Linux distro website), and the program finds the right hash for your selected file.
- **Hash file support:**  
  Load any standard hash list or SHA256SUMS.txt and auto-populate the hash field.
- **GPG signature verification:**  
  - Select your Linux distribution, and the tool fetches and verifies the official public signing key automatically.
  - Select or paste both the hash list (SHA256SUMS) and the signature (SHA256SUMS.gpg), and the program verifies authenticity.
  - You can **copy/paste the .gpg signature directly from your browser** – no need to save as a file first!
- **Flexible:**  
  Works for all Linux ISOs and any files you want to check.
- **Clear result reporting** with color-coded output.

## Why verify downloads?

- Hashes (SHA256, etc.) ensure the file was not corrupted or changed.
- GPG signature on the hash list guarantees the *authenticity* of the hashes themselves (not just file integrity, but also security).

## Quickstart

1. **Select the file** you want to verify (ISO, etc.).
2. **Check hash**:
   - Paste the hash in the correct field (SHA256 etc.), **OR**
   - Paste the full hash list in the "Paste SHA*SUMS text" box, click "Parse hash from pasted text", and let the tool auto-fill the correct value.
   - Click "Check hash" for instant feedback.
3. **Verify signature (for distros that support it):**
   - Download or copy the full `SHA256SUMS` (or `sha256sum.txt`) and select as "SHA256SUMS file".
   - Download or copy the GPG signature (`SHA256SUMS.gpg` or `sha256sum.txt.gpg`) – you can paste it as text!
   - Select your distro (or paste a key ID).
   - Click "Verify signature".

## Supported distros

- **Full GPG support:** Ubuntu, Linux Mint, Debian, Fedora, Arch, Kali, Manjaro, Tails, Qubes, Zorin, elementary, OpenSUSE (and more).
- **Hash-only (no GPG):**  
  Some distributions, such as Pop!_OS, only provide SHA256 hashes and do **not** offer a signed hash list.  
  In this case, simply use the hash check functionality.

## Example workflow

- **Ubuntu/Mint:** Download both SHA256SUMS and SHA256SUMS.gpg.  
  Use both to fully verify your ISO (and trust you have the official, unmodified download!).
- **Pop!_OS:**  
  Only SHA256 hash is provided.  
  Paste this into the SHA256 field and check the hash – you get integrity, but not mathematical authenticity.

## Requirements

- Python 3.8+
- Packages: `python-gnupg`, `tkinter`
- For signature verification: GnuPG (gpg) must be installed and in your system PATH.

## Security note

**Always use GPG verification if your distribution supports it!**  
This ensures your ISO is *not just* unmodified, but also that it comes from the official developers.

If your distro only offers SHA256:  
- Make sure you download hashes over HTTPS, and double-check that you are on the official website.

---

### License

MIT License  
Created by [your username]

---

### Feedback and contributions welcome!

Open an issue or PR if you have ideas or find bugs.  
This tool is for everyone who wants easy, secure, *offline* ISO verification!

