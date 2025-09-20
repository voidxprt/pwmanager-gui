# 🔐 PWManager GUI  
_A modern, secure, and feature-rich **desktop password manager** built with Python, PySide6, and cryptography._  

<p align="center">
  
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/voidxprt/pwmanager-gui?style=for-the-badge&color=blue)  
![GitHub top language](https://img.shields.io/github/languages/top/voidxprt/pwmanager-gui?style=for-the-badge&color=yellow)  
![GitHub issues](https://img.shields.io/github/issues/voidxprt/pwmanager-gui?style=for-the-badge&color=orange)  
![GitHub stars](https://img.shields.io/github/stars/voidxprt/pwmanager-gui?style=for-the-badge&color=gold)  
![GitHub forks](https://img.shields.io/github/forks/voidxprt/pwmanager-gui?style=for-the-badge&color=lightblue)  


</p>

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

## 📸 Screenshots 
<img width="982" height="514" alt="Screenshot (57)" src="https://github.com/user-attachments/assets/cbc233a7-d976-4275-8b67-9e6dd8d07aa5" />
<img width="1366" height="708" alt="Screenshot (56)" src="https://github.com/user-attachments/assets/c6ba5cf8-2879-46ca-a839-60335524f94c" />
<img width="1362" height="717" alt="Screenshot (55)" src="https://github.com/user-attachments/assets/90c0bdbe-1694-43ea-a6e9-c493056f0053" />
<img width="1366" height="721" alt="Screenshot (54)" src="https://github.com/user-attachments/assets/20bf7368-effe-4c2d-a020-404afa165e04" />
<img width="1362" height="721" alt="Screenshot (53)" src="https://github.com/user-attachments/assets/2ef9aeea-2f81-45f2-a0a9-11d8392eecf3" />
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
