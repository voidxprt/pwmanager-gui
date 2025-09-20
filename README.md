````markdown
<div align="center">
  
# 🔐 PWManager GUI  
A modern, secure, and feature-rich **desktop password manager** built with Python, PySide6, and cryptography.  

![GitHub repo size](https://img.shields.io/github/repo-size/voidxprt/pwmanager-gui?color=blue&style=for-the-badge)  
![GitHub license](https://img.shields.io/github/license/voidxprt/pwmanager-gui?style=for-the-badge&color=green)  
![GitHub last commit](https://img.shields.io/github/last-commit/voidxprt/pwmanager-gui?style=for-the-badge&color=purple)  
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)  
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20MacOS-lightgrey?style=for-the-badge)  

</div>

---

## ✨ Features
- 🗝️ **Master Password Vault** with strong encryption (PBKDF2HMAC + Fernet).  
- 🎨 **Modern GUI** using PySide6 (dark & light themes).  
- 🔒 **Auto-lock** after inactivity (configurable).  
- 📋 **Clipboard auto-clear** (prevents leaks).  
- 🧩 **Password generator** (random, passphrase, pronounceable, PIN).  
- 📊 **Strength checker** with entropy + suggestions.  
- ⭐ **Favorites, tags, custom fields, and attachments**.  
- 📂 **Export, import, and backup** encrypted vaults.  
- 📑 **Password history tracking** for every entry.  
- 🖥️ **Dashboard with analytics** (average entropy, reused passwords, health score).  
- ⚙️ **Tools**: master password change, integrity check, weak/reused password reports.  

---

## 📸 Screenshots (Coming Soon)
> Add your own screenshots here (GUI, generator tab, vault tab, reports, etc.)

---

## 🚀 Installation

Clone the repository:
```bash
git clone https://github.com/voidxprt/pwmanager-gui.git
cd pwmanager-gui
````

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the app:

```bash
python app.py
```

Run the CLI decrypt tool:

```bash
python decrypt.py
```

---

## 📦 Requirements

* Python **3.10+**
* [PySide6](https://pypi.org/project/PySide6/)
* [cryptography](https://pypi.org/project/cryptography/)

Install them with:

```bash
pip install PySide6 cryptography
```

---

## 🛡️ Security Notes

* ✅ Vaults are encrypted with **PBKDF2-HMAC-SHA256** and **Fernet AES-128-CBC HMAC-SHA256**.
* ✅ Default **240,000 iterations** for KDF.
* ✅ Master password strength checked before vault creation.
* ✅ Auto-lock and clipboard clear features built-in.
* ⚠️ For maximum security, always use a **strong master password**.
* ⚠️ CLI tool prints passwords in plaintext (use in trusted environments only).

---

## 📂 Project Structure

```
pwmanager-gui/
├── app.py             # Main GUI password manager
├── decrypt.py         # CLI vault decrypter
├── requirements.txt   # Dependencies
├── README.md          # This file
├── LICENSE            # License file
└── .gitignore         # Git ignore rules
```

---

## 🛠️ Building Executables (Optional)

You can package the app into an `.exe` with [PyInstaller](https://pyinstaller.org/):

GUI app:

```bash
pyinstaller --onefile --noconsole app.py
```

CLI tool:

```bash
pyinstaller --onefile --console decrypt.py
```

Executables will appear in the `dist/` folder.

---

## 🌟 Roadmap

* [ ] 🔑 Add support for Argon2 KDF (stronger than PBKDF2).
* [ ] 🌐 Sync vaults via cloud (Dropbox/Google Drive/OneDrive).
* [ ] 📱 Mobile companion app.
* [ ] 🔍 Better search & filtering (regex, fuzzy).
* [ ] 🎨 Custom themes & user CSS.
* [ ] 🧪 Automated test suite.

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you’d like to change.

Steps:

1. Fork the repo
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for details.

---

<div align="center">

### 🎉 Thank you for checking out **PWManager GUI**!

⭐ If you like this project, give it a star on GitHub — it helps a lot!

</div>
```
