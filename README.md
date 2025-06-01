# HashCheckGUI

**HashCheckGUI** is a free, open source utility for verifying file hashes using a simple graphical interface.  
It supports SHA1, SHA256, SHA384, and SHA512 – all at once or individually.  
Ideal for verifying downloads (ISOs, software installers, documents, etc.) to ensure integrity and authenticity.

---

## Features

- Simple, intuitive GUI – no command line required
- Check SHA1, SHA256, SHA384, and SHA512 (all fields optional)
- Instant visual feedback (green = match, red = mismatch)
- No data is uploaded or logged – everything runs locally
- 100% open source – view, modify, or share as you wish

---

## Usage

1. **Run the program:**
   - If you have Python 3.x installed:  
     ```sh
     python hashcheck_gui.py
     ```
   - Or, download the `.exe` from [Releases](https://github.com/yourusername/HashCheckGUI/releases) and double-click to start (no installation required).

2. **Select the file** you want to check (e.g., a downloaded ISO or installer) by clicking "Browse..."

3. **Paste the official hash values** (SHA1, SHA256, SHA384, SHA512) in the relevant fields.
   - You can fill one or several fields – only filled fields are checked.

4. **Click "Check hash".**
   - A popup window will show you which hashes match (green) or do not match (red).

---

## Building your own .exe

If you want to build the Windows executable yourself (recommended for full transparency):

```sh
python -m pip install pyinstaller
python -m pyinstaller hashcheck_gui.py --onefile --noconsole
