#!/usr/bin/env python3
"""
pwmanager_gui_fixed.py

Single-file desktop password manager with a modern theme (PySide6).
Includes many features (security, UX, vault tools, generation, analytics).

Dependencies:
    pip install PySide6 cryptography

Run:
    python pwmanager_gui_fixed.py
"""

import sys
import os
import json
import base64
import secrets
import string
import math
import hashlib
import datetime
import gzip
from functools import partial
from typing import List, Dict, Any, Optional

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QTextEdit, QComboBox, QSpinBox, QCheckBox,
    QTabWidget, QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QFormLayout, QGroupBox, QInputDialog, QDialog, QDialogButtonBox,
    QAbstractItemView, QSplitter, QListWidget, QListWidgetItem, QStyle
)
from PySide6.QtCore import Qt, QTimer, QEvent
from PySide6.QtGui import QIcon, QKeySequence, QColor, QAction, QShortcut

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet, InvalidToken
except Exception as e:
    raise SystemExit("Install 'cryptography' package: pip install cryptography") from e

# ------------------ Config ------------------
VAULT_PATH = os.path.expanduser("~/.pwmanager_gui_vault.json")
BACKUP_DIR = os.path.expanduser("~")
KDF_ITERATIONS = 240_000
CLIP_CLEAR_MS = 15_000  # milliseconds (clipboard auto-clear)
MIN_MASTER_PW_LEN = 10
AUTO_LOCK_MS = 5 * 60 * 1000  # 5 minutes default inactivity lock (ms)

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "111111",
    "1234567", "sunshine", "iloveyou", "princess", "admin", "welcome", "666666"
}

SAMPLE_WORDS = [
    "apple","banana","orange","table","window","river","mountain","book","silent",
    "gold","silver","ocean","forest","haven","mirror","stone","bridge","cloud",
    "ember","flame","copper","atlas","nebula","quantum","pixel","nova"
]

VOWELS = "aeiou"
CONSONANTS = "".join(sorted(set(string.ascii_lowercase) - set(VOWELS)))

# ------------------ Crypto ------------------
class CryptoManager:
    def __init__(self, salt: bytes, iterations: int = KDF_ITERATIONS):
        self.salt = salt
        self.iterations = iterations
        self.backend = default_backend()

    def derive_key(self, master_password: str) -> bytes:
        pw = master_password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=self.iterations,
            backend=self.backend
        )
        key = kdf.derive(pw)
        return base64.urlsafe_b64encode(key)

    def get_fernet(self, master_password: str) -> Fernet:
        key = self.derive_key(master_password)
        return Fernet(key)

# ------------------ Vault ------------------
class Vault:
    def __init__(self, path: str = VAULT_PATH):
        self.path = path
        self.header: Dict[str, Any] = {}
        self._plaintext_vault: Dict[str, Any] = {"entries": {}, "meta": {"created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "saved_passwords": [], "templates": []}}
        self.fernet: Optional[Fernet] = None
        self.read_only = False

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def initialize_new(self, master_password: str, security_question: Optional[str] = None, security_answer: Optional[str] = None):
        salt = os.urandom(16)
        self.header = {
            "version": 2,
            "salt": base64.urlsafe_b64encode(salt).decode('utf-8'),
            "kdf_iterations": KDF_ITERATIONS,
        }
        if security_question and security_answer:
            sec_salt = os.urandom(12)
            hashed = hashlib.sha256(sec_salt + security_answer.encode('utf-8')).hexdigest()
            self.header['security'] = {
                "question": security_question,
                "salt": base64.urlsafe_b64encode(sec_salt).decode('utf-8'),
                "answer_hash": hashed
            }
        crypto = CryptoManager(salt, KDF_ITERATIONS)
        self.fernet = crypto.get_fernet(master_password)
        self._plaintext_vault = {"entries": {}, "meta": {"created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "saved_passwords": [], "templates": []}}
        self._write_encrypted()

    def load(self, master_password: str) -> bool:
        if not self.exists():
            raise FileNotFoundError("Vault file not found")
        with open(self.path, 'r') as f:
            j = json.load(f)
        self.header = {
            "version": j.get('version',1),
            "salt": j['salt'],
            "kdf_iterations": j.get('kdf_iterations', KDF_ITERATIONS)
        }
        salt = base64.urlsafe_b64decode(self.header['salt'].encode('utf-8'))
        crypto = CryptoManager(salt, self.header['kdf_iterations'])
        fernet = crypto.get_fernet(master_password)
        try:
            dec = fernet.decrypt(base64.urlsafe_b64decode(j['data'].encode('utf-8')))
            self._plaintext_vault = json.loads(dec.decode('utf-8'))
            self._plaintext_vault.setdefault('meta', {})
            self._plaintext_vault['meta'].setdefault('saved_passwords', [])
            self._plaintext_vault['meta'].setdefault('templates', [])
            self.fernet = fernet
            return True
        except InvalidToken:
            return False

    def _write_encrypted(self, compress: bool = False):
        if self.fernet is None:
            raise RuntimeError("Fernet not set")
        serialized = json.dumps(self._plaintext_vault, ensure_ascii=False).encode('utf-8')
        if compress:
            serialized = gzip.compress(serialized)
        token = self.fernet.encrypt(serialized)
        out = {
            "version": self.header.get('version',1),
            "salt": self.header['salt'],
            "kdf_iterations": self.header.get('kdf_iterations', KDF_ITERATIONS),
            "data": base64.urlsafe_b64encode(token).decode('utf-8')
        }
        with open(self.path, 'w') as f:
            json.dump(out, f, indent=2)
        try:
            os.chmod(self.path, 0o600)
        except Exception:
            pass

    # CRUD
    def list_entries(self) -> List[Dict[str, Any]]:
        return list(self._plaintext_vault.get('entries', {}).values())

    def get_entry(self, label: str) -> Optional[Dict[str, Any]]:
        return self._plaintext_vault.get('entries', {}).get(label)

    def add_entry(self, label: str, username: str, password: str, notes: str = "", tags: List[str] = [], favorite: bool=False, custom_fields: Dict[str,str]=None):
        if self.read_only:
            raise PermissionError("Vault is read-only")
        entries = self._plaintext_vault.setdefault('entries', {})
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if label in entries:
            raise ValueError("Label exists")
        entries[label] = {
            "label": label,
            "username": username,
            "password": password,
            "notes": notes,
            "tags": tags,
            "favorite": favorite,
            "custom_fields": custom_fields or {},
            "attachments": [],
            "created_at": now,
            "last_updated": now,
            "history": [{"password": password, "changed_at": now}]
        }
        self._write_encrypted()

    def update_entry(self, label: str, username: Optional[str]=None, password: Optional[str]=None,
                     notes: Optional[str]=None, tags: Optional[List[str]]=None, favorite: Optional[bool]=None,
                     custom_fields: Optional[Dict[str,str]]=None):
        if self.read_only:
            raise PermissionError("Vault is read-only")
        entries = self._plaintext_vault.setdefault('entries', {})
        if label not in entries:
            raise KeyError("No such entry")
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        e = entries[label]
        if username is not None:
            e['username'] = username
        if password is not None and password != e.get('password'):
            e.setdefault('history', []).append({'password': password, 'changed_at': now})
            e['password'] = password
        if notes is not None:
            e['notes'] = notes
        if tags is not None:
            e['tags'] = tags
        if favorite is not None:
            e['favorite'] = favorite
        if custom_fields is not None:
            e['custom_fields'] = custom_fields
        e['last_updated'] = now
        self._write_encrypted()

    def delete_entry(self, label: str):
        if self.read_only:
            raise PermissionError("Vault is read-only")
        entries = self._plaintext_vault.setdefault('entries', {})
        if label in entries:
            del entries[label]
            self._write_encrypted()
        else:
            raise KeyError("No such entry")

    def search_entries(self, q: str) -> List[Dict[str, Any]]:
        qlow = q.lower()
        results = []
        for e in self.list_entries():
            if (qlow in e['label'].lower() or qlow in (e.get('username') or '').lower() or
                qlow in (e.get('notes') or '').lower() or any(qlow in t.lower() for t in e.get('tags', [])) or
                any(qlow in (v or '').lower() for v in e.get('custom_fields', {}).values())):
                results.append(e)
        return results

    def change_master_password(self, old_master: str, new_master: str):
        if self.read_only:
            raise PermissionError("Vault is read-only")
        salt = os.urandom(16)
        crypto = CryptoManager(salt, self.header.get('kdf_iterations', KDF_ITERATIONS))
        new_fernet = crypto.get_fernet(new_master)
        self.fernet = new_fernet
        self.header['salt'] = base64.urlsafe_b64encode(salt).decode('utf-8')
        self._write_encrypted()

    def export_encrypted_copy(self, out_path: str):
        with open(self.path, 'rb') as src:
            data = src.read()
        with open(out_path, 'wb') as dst:
            dst.write(data)

    def import_encrypted_copy(self, in_path: str):
        with open(in_path, 'r') as src:
            j = json.load(src)
        with open(self.path, 'w') as dst:
            json.dump(j, dst, indent=2)

    # attachments
    def attach_file_to_entry(self, label: str, file_path: str):
        if self.read_only:
            raise PermissionError("Vault is read-only")
        entry = self.get_entry(label)
        if not entry:
            raise KeyError("Entry missing")
        with open(file_path, 'rb') as f:
            data = f.read()
        b64 = base64.b64encode(data).decode('utf-8')
        entry.setdefault('attachments', []).append({"name": os.path.basename(file_path), "data_b64": b64, "attached_at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
        entry['last_updated'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._write_encrypted()

    # backups
    def backup(self):
        ts = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        out = os.path.join(BACKUP_DIR, f".pwmanager_gui_vault_backup_{ts}.json")
        self.export_encrypted_copy(out)
        return out

    # integrity
    def integrity_check(self) -> bool:
        try:
            with open(self.path, 'r') as f:
                j = json.load(f)
            token = base64.urlsafe_b64decode(j['data'].encode('utf-8'))
            if self.fernet:
                _ = self.fernet.decrypt(token)
                return True
            else:
                return False
        except Exception:
            return False

# ------------------ Password gen & check ------------------
class PasswordGenerator:
    def generate(self, length: int = 16, use_lower=True, use_upper=True,
                 use_digits=True, use_symbols=True, exclude_ambiguous=True) -> str:
        pool = ""
        if use_lower:
            pool += string.ascii_lowercase
        if use_upper:
            pool += string.ascii_uppercase
        if use_digits:
            pool += string.digits
        if use_symbols:
            pool += "!@#$%^&*()-_=+[]{};:,.<>/?"
        if exclude_ambiguous:
            for ch in "Il1O0|`'\"":
                pool = pool.replace(ch, "")
        if not pool:
            raise ValueError("Empty character pool")
        return ''.join(secrets.choice(pool) for _ in range(length))

    def generate_passphrase(self, words: int = 4, separator: str = "-", wordlist: Optional[List[str]] = None) -> str:
        wl = wordlist if wordlist else SAMPLE_WORDS
        return separator.join(secrets.choice(wl) for _ in range(words))

    def generate_pronounceable(self, length: int = 12) -> str:
        out = []
        use_vowel = bool(secrets.randbelow(2))
        for _ in range(length):
            out.append(secrets.choice(VOWELS) if use_vowel else secrets.choice(CONSONANTS))
            use_vowel = not use_vowel
        s = ''.join(out)
        if secrets.randbelow(2):
            idx = secrets.randbelow(len(s))
            s = s[:idx] + s[idx].upper() + s[idx+1:]
        if secrets.randbelow(3) == 0:
            s = s + str(secrets.choice(string.digits))
        return s

    def generate_pin(self, length: int = 4) -> str:
        return ''.join(secrets.choice(string.digits) for _ in range(length))

class StrengthChecker:
    def entropy_bits(self, password: str) -> float:
        pool = 0
        if any(c.islower() for c in password): pool += 26
        if any(c.isupper() for c in password): pool += 26
        if any(c.isdigit() for c in password): pool += 10
        if any(c in string.punctuation for c in password): pool += len(string.punctuation)
        if pool == 0:
            return 0.0
        return len(password) * math.log2(pool)

    def contains_common_patterns(self, password: str) -> List[str]:
        p = password.lower()
        flags = []
        if p in COMMON_PASSWORDS:
            flags.append("common_password")
        if any(seq in p for seq in ["123", "111", "000", "abc", "qwerty"]):
            flags.append("simple_sequence")
        if any(p.startswith(x) for x in ["qwerty","asdf","zxcv"]):
            flags.append("keyboard_pattern")
        return flags

    def score(self, password: str) -> Dict[str, Any]:
        ent = self.entropy_bits(password)
        issues = []
        patterns = self.contains_common_patterns(password)
        if patterns:
            issues.extend(patterns)
        if len(password) < 8:
            issues.append("too_short")
        if len(password) >= 8 and ent < 40:
            issues.append("low_entropy")
        if len(password) >= 12 and ent >= 60:
            strength = "strong"
        elif ent >= 40:
            strength = "moderate"
        else:
            strength = "weak"
        return {"entropy_bits": round(ent,2), "strength": strength, "issues": issues}

    def suggest_alternatives(self, password: str, count: int = 5) -> List[str]:
        gen = PasswordGenerator()
        suggestions = []
        for i in range(count):
            if len(password) < 12:
                s = password + secrets.choice("!@#$%&*")
            else:
                s = password
            s_list = list(s)
            for _ in range(max(1, len(s)//10)):
                idx = secrets.randbelow(len(s_list))
                s_list[idx] = self._substitute_char(s_list[idx])
            suggestions.append(''.join(s_list))
        if any(w in password.lower() for w in SAMPLE_WORDS):
            suggestions.append(gen.generate_passphrase(words=4))
        while len(suggestions) < count:
            suggestions.append(gen.generate(length=max(16, len(password)+4)))
        return suggestions[:count]

    def _substitute_char(self, ch: str) -> str:
        subs = {'a':'@','s':'$','o':'0','i':'1','e':'3','l':'1','t':'7'}
        cl = ch.lower()
        if cl in subs and secrets.randbelow(2):
            out = subs[cl]
            if ch.isupper():
                out = out.upper()
            return out
        return secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*")

# ------------------ UI ------------------
DARK_QSS = """
QWidget { background: #0f0f10; color: #e6e6e6; font-family: 'Segoe UI', 'Roboto', 'Helvetica', sans-serif; }
QLineEdit, QTextEdit, QSpinBox, QComboBox { background: #1a1a1b; color: #e6e6e6; border: 1px solid #313235; padding: 6px; border-radius: 6px; }
QPushButton { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #2b2b2c, stop:1 #1a1a1b); color: #fff; border-radius: 8px; padding: 8px 12px; }
QPushButton:hover { background: #3a3a3b; }
QPushButton:pressed { background: #222223; }
QTabWidget::pane { border: none; }
QTabBar::tab { background: #121213; padding: 8px 12px; margin: 2px; border-radius: 6px; }
QTabBar::tab:selected { background: #1f1f20; }
QHeaderView::section { background: #121213; padding: 6px; border-bottom: 1px solid #262627; }
QTableWidget { gridline-color: #262627; }
QGroupBox { border: 1px solid #262627; margin-top: 8px; border-radius: 8px; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }
"""

LIGHT_QSS = """
QWidget { background: #f7f7f8; color: #111; font-family: 'Segoe UI', 'Roboto', 'Helvetica', sans-serif; }
QLineEdit, QTextEdit, QSpinBox, QComboBox { background: #fff; color: #111; border: 1px solid #ccc; padding: 6px; border-radius: 6px; }
QPushButton { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #e6e6e6, stop:1 #fff); color: #111; border-radius: 8px; padding: 8px 12px; }
QPushButton:hover { background: #ddd; }
QTabWidget::pane { border: none; }
QTabBar::tab { background: #eee; padding: 8px 12px; margin: 2px; border-radius: 6px; }
QTabBar::tab:selected { background: #fff; }
QHeaderView::section { background: #f0f0f0; padding: 6px; border-bottom: 1px solid #ddd; }
QTableWidget { gridline-color: #ddd; }
QGroupBox { border: 1px solid #ddd; margin-top: 8px; border-radius: 8px; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }
"""

class MasterPasswordDialog(QDialog):
    def __init__(self, creating=False, security_question: Optional[str]=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create Master Password" if creating else "Enter Master Password")
        self.resize(520,160)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.pw = QLineEdit(); self.pw.setEchoMode(QLineEdit.Password)
        form.addRow("Master Password:", self.pw)
        if creating:
            self.confirm = QLineEdit(); self.confirm.setEchoMode(QLineEdit.Password)
            form.addRow("Confirm Password:", self.confirm)
            self.sec_q = QLineEdit(); self.sec_a = QLineEdit()
            form.addRow("Optional unlock question:", self.sec_q)
            form.addRow("Optional unlock answer:", self.sec_a)
        else:
            if security_question:
                self.sec_a = QLineEdit(); self.sec_a.setEchoMode(QLineEdit.Password)
                form.addRow(f"Security question: {security_question}", QLabel(""))
                form.addRow("Answer (optional if set):", self.sec_a)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_passwords(self):
        if hasattr(self, 'confirm'):
            return self.pw.text(), self.confirm.text(), getattr(self, 'sec_q', None).text(), getattr(self, 'sec_a', None).text()
        return self.pw.text(), None, None, getattr(self, 'sec_a', None).text() if hasattr(self, 'sec_a') else (None)

class EntryEditor(QDialog):
    def __init__(self, existing: Optional[Dict[str,Any]] = None, parent=None, vault: Optional[Vault]=None, checker: Optional[StrengthChecker]=None):
        super().__init__(parent)
        self.setWindowTitle('Entry')
        self.resize(720,460)
        self.vault = vault
        self.checker = checker or StrengthChecker()
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.label = QLineEdit(); self.username = QLineEdit(); self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.show_pw = QCheckBox("Show password"); self.show_pw.stateChanged.connect(self._toggle_show_pw)
        self.strength_label = QLabel("Strength: -")
        self.notes = QTextEdit(); self.tags = QLineEdit()
        self.favorite = QCheckBox("Favorite / Pin")
        self.custom_fields = QTextEdit(); self.custom_fields.setPlaceholderText("key:value per line")
        form.addRow('Label:', self.label)
        form.addRow('Username:', self.username)
        pw_h = QHBoxLayout()
        pw_h.addWidget(self.password); pw_h.addWidget(self.show_pw); pw_h.addWidget(self.strength_label)
        form.addRow('Password (leave empty to generate):', pw_h)
        form.addRow('Tags (comma separated or multi-level with /):', self.tags)
        form.addRow('Favorite:', self.favorite)
        form.addRow('Custom fields:', self.custom_fields)
        form.addRow('Notes (Markdown supported):', self.notes)
        attach_btn = QPushButton("Attach file"); attach_btn.clicked.connect(self._attach_file)
        self.attach_list = QListWidget()
        form.addRow(attach_btn, self.attach_list)
        layout.addLayout(form)
        btns = QHBoxLayout()
        gen_btn = QPushButton('Generate'); gen_btn.clicked.connect(self._on_generate)
        gen_save_btn = QPushButton('Save generated to vault') ; gen_save_btn.clicked.connect(self._save_generated_pwd)
        history_btn = QPushButton('View History'); history_btn.clicked.connect(self._view_history)
        ok_cancel = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        ok_cancel.accepted.connect(self.accept); ok_cancel.rejected.connect(self.reject)
        btns.addWidget(gen_btn); btns.addWidget(gen_save_btn); btns.addWidget(history_btn); btns.addStretch(); btns.addWidget(ok_cancel)
        layout.addLayout(btns)
        if existing:
            self.label.setText(existing.get('label',''))
            self.label.setReadOnly(True)
            self.username.setText(existing.get('username',''))
            self.password.setText(existing.get('password',''))
            self.notes.setPlainText(existing.get('notes',''))
            self.tags.setText(','.join(existing.get('tags',[])))
            self.favorite.setChecked(bool(existing.get('favorite', False)))
            cf = existing.get('custom_fields', {})
            self.custom_fields.setPlainText('\n'.join(f"{k}:{v}" for k,v in cf.items()))
            for att in existing.get('attachments', []):
                item = QListWidgetItem(f"{att.get('name')} (attached {att.get('attached_at', '')})")
                self.attach_list.addItem(item)
        self.password.textChanged.connect(self._update_strength)
        self._update_strength()

    def _toggle_show_pw(self, state):
        self.password.setEchoMode(QLineEdit.Normal if state == Qt.Checked else QLineEdit.Password)

    def _update_strength(self):
        pwd = self.password.text()
        if not pwd:
            self.strength_label.setText("Strength: -")
            return
        r = self.checker.score(pwd)
        self.strength_label.setText(f"Strength: {r['strength']} ({r['entropy_bits']} bits)")

    def _on_generate(self):
        pw = PasswordGenerator().generate(length=16)
        self.password.setText(pw)

    def _save_generated_pwd(self):
        pw = self.password.text()
        if not pw:
            QMessageBox.warning(self, "Empty", "No generated password to save")
            return
        if self.vault:
            meta = self.vault._plaintext_vault.setdefault('meta', {})
            saved = meta.setdefault('saved_passwords', [])
            saved.append({"pw": pw, "saved_at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
            self.vault._write_encrypted()
            QMessageBox.information(self, "Saved", "Generated password saved to vault meta (encrypted)")

    def _view_history(self):
        label = self.label.text().strip()
        if not label:
            QMessageBox.warning(self, "No label", "Entry hasn't been saved yet")
            return
        entry = self.vault.get_entry(label) if self.vault else None
        if not entry:
            QMessageBox.information(self, "No history", "No history found for this entry")
            return
        hist = entry.get('history', [])
        text = '\n'.join([f"{h['changed_at']}: {h['password']}" for h in hist])
        dlg = QDialog(self)
        dlg.setWindowTitle("Password History")
        dlg.resize(600,400)
        l = QVBoxLayout(dlg)
        te = QTextEdit(); te.setReadOnly(True); te.setPlainText(text)
        l.addWidget(te)
        btn = QDialogButtonBox(QDialogButtonBox.Ok); btn.accepted.connect(dlg.accept)
        l.addWidget(btn)
        dlg.exec()

    def _attach_file(self):
        label = self.label.text().strip()
        path, _ = QFileDialog.getOpenFileName(self, "Select file to attach", os.path.expanduser("~"))
        if not path:
            return
        if label and self.vault and self.vault.get_entry(label):
            try:
                self.vault.attach_file_to_entry(label, path)
                QMessageBox.information(self, "Attached", "File attached to existing entry (encrypted)")
                self.attach_list.addItem(os.path.basename(path))
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))
        else:
            with open(path, 'rb') as f:
                data = f.read()
            b64 = base64.b64encode(data).decode('utf-8')
            item = QListWidgetItem(f"{os.path.basename(path)} (local)")
            item.setData(Qt.UserRole, {"name": os.path.basename(path), "data_b64": b64})
            self.attach_list.addItem(item)

    def get_values(self):
        tags = [t.strip() for t in self.tags.text().split(',') if t.strip()]
        cf_lines = [l.strip() for l in self.custom_fields.toPlainText().splitlines() if l.strip()]
        cf = {}
        for line in cf_lines:
            if ':' in line:
                k,v = line.split(':',1)
                cf[k.strip()] = v.strip()
        attaches = []
        for i in range(self.attach_list.count()):
            it = self.attach_list.item(i)
            data = it.data(Qt.UserRole)
            if data:
                attaches.append({"name": data['name'], "data_b64": data['data_b64'], "attached_at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
        return (self.label.text().strip(), self.username.text().strip(), self.password.text(), self.notes.toPlainText().strip(), tags, self.favorite.isChecked(), cf, attaches)

# ------------------ Main Window ------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PWManager — Desktop")
        self.setMinimumSize(1000, 700)
        self.vault = Vault(VAULT_PATH)
        self.generator = PasswordGenerator()
        self.checker = StrengthChecker()
        self.master_password = None
        self.auto_lock_ms = AUTO_LOCK_MS
        self.auto_lock_timer = QTimer(self)
        self.auto_lock_timer.setInterval(self.auto_lock_ms)
        self.auto_lock_timer.timeout.connect(self._lock_due_to_inactivity)
        self.interaction_events = (QEvent.MouseButtonPress, QEvent.KeyPress, QEvent.MouseMove)
        self.read_only_mode = False
        self.theme = 'dark'
        self._build_ui()
        self.setStyleSheet(DARK_QSS)
        QShortcut(QKeySequence("Ctrl+N"), self, activated=self._on_add_entry)
        QShortcut(QKeySequence("Ctrl+F"), self, activated=lambda: self.search_input.setFocus())
        QShortcut(QKeySequence("Ctrl+L"), self, activated=self._lock_now)
        QShortcut(QKeySequence("Ctrl+Shift+C"), self, activated=self._on_copy_password)
        self._ensure_vault()
        self._start_activity_monitoring()

    def eventFilter(self, obj, event):
        if event.type() in self.interaction_events:
            self._reset_auto_lock_timer()
        return super().eventFilter(obj, event)

    def _start_activity_monitoring(self):
        QApplication.instance().installEventFilter(self)
        self._reset_auto_lock_timer()

    def _reset_auto_lock_timer(self):
        if self.auto_lock_ms <= 0:
            return
        self.auto_lock_timer.start()

    def _lock_due_to_inactivity(self):
        self.auto_lock_timer.stop()
        self.master_password = None
        QMessageBox.information(self, "Locked", "Vault locked due to inactivity. Please re-enter master password.")
        self._prompt_unlock()

    def _lock_now(self):
        self.master_password = None
        QMessageBox.information(self, "Locked", "Vault locked. Please re-enter master password.")
        self._prompt_unlock()

    def _prompt_unlock(self):
        sec_q = None
        if self.vault.header.get('security'):
            sec_q = self.vault.header['security'].get('question')
        dlg = MasterPasswordDialog(creating=False, security_question=sec_q, parent=self)
        if dlg.exec() != QDialog.Accepted:
            sys.exit(0)
        pw, _, _, sec_a = dlg.get_passwords()
        ok = self.vault.load(pw)
        if not ok:
            QMessageBox.warning(self, "Unlock Failed", "Incorrect master password.")
            dlg2 = MasterPasswordDialog(creating=False, security_question=sec_q, parent=self)
            if dlg2.exec() != QDialog.Accepted:
                sys.exit(0)
            pw2, _, _, sec_a2 = dlg2.get_passwords()
            ok = self.vault.load(pw2)
            if not ok:
                QMessageBox.critical(self, "Error", "Failed to unlock")
                sys.exit(1)
            self.master_password = pw2
        else:
            self.master_password = pw
        self._refresh_vault_table()
        self._reset_auto_lock_timer()

    def _ensure_vault(self):
        if not self.vault.exists():
            dlg = MasterPasswordDialog(creating=True, parent=self)
            if dlg.exec() != QDialog.Accepted:
                sys.exit(0)
            pw, confirm, sec_q, sec_a = dlg.get_passwords()
            score = self.checker.score(pw)
            if not pw or pw != confirm or len(pw) < MIN_MASTER_PW_LEN or score['strength'] == 'weak':
                QMessageBox.critical(self, "Error", f"Master password invalid, too weak, or does not match (min {MIN_MASTER_PW_LEN}).")
                sys.exit(1)
            self.vault.initialize_new(pw, sec_q or None, sec_a or None)
            self.master_password = pw
        else:
            attempts = 0
            while attempts < 5:
                dlg = MasterPasswordDialog(creating=False, parent=self)
                if dlg.exec() != QDialog.Accepted:
                    sys.exit(0)
                pw, _, _, sec_a = dlg.get_passwords()
                ok = self.vault.load(pw)
                if ok:
                    self.master_password = pw
                    break
                else:
                    sec = self.vault.header.get('security')
                    if sec and sec_a:
                        try:
                            salt = base64.urlsafe_b64decode(sec['salt'].encode('utf-8'))
                            if hashlib.sha256(salt + sec_a.encode('utf-8')).hexdigest() == sec.get('answer_hash'):
                                QMessageBox.information(self, "Security Answer Verified", "Security answer verified. You may now set a new master password.")
                                new_dlg = MasterPasswordDialog(creating=True, parent=self)
                                if new_dlg.exec() != QDialog.Accepted:
                                    sys.exit(0)
                                new_pw, confirm, new_q, new_a = new_dlg.get_passwords()
                                score = self.checker.score(new_pw)
                                if not new_pw or new_pw != confirm or len(new_pw) < MIN_MASTER_PW_LEN or score['strength'] == 'weak':
                                    QMessageBox.critical(self, "Error", f"Master password invalid or too weak (min {MIN_MASTER_PW_LEN}).")
                                    sys.exit(1)
                                confirm_reset = QMessageBox.question(self, "Reset Vault", "Reset vault (this will wipe existing encrypted content)?", QMessageBox.Yes | QMessageBox.No)
                                if confirm_reset == QMessageBox.Yes:
                                    self.vault.initialize_new(new_pw, new_q or None, new_a or None)
                                    self.master_password = new_pw
                                    break
                        except Exception:
                            pass
                    QMessageBox.warning(self, "Unlock Failed", "Incorrect master password.")
                    attempts += 1
            if attempts >= 5 and not self.master_password:
                QMessageBox.critical(self, "Error", "Too many failed attempts")
                sys.exit(1)
        self._refresh_vault_table()

    def _build_ui(self):
        tabs = QTabWidget()
        tabs.addTab(self._build_generate_tab(), "Generator")
        tabs.addTab(self._build_check_tab(), "Strength")
        tabs.addTab(self._build_vault_tab(), "Vault")
        tabs.addTab(self._build_tools_tab(), "Tools")
        tabs.addTab(self._build_dashboard_tab(), "Dashboard")
        self.setCentralWidget(tabs)

    # ----- Generator Tab -----
    def _build_generate_tab(self):
        w = QWidget(); layout = QVBoxLayout(w)
        form = QGroupBox("Generate Password")
        f_layout = QFormLayout()
        self.gen_mode = QComboBox(); self.gen_mode.addItems(["Random","Passphrase","Pronounceable","PIN"])
        self.gen_length = QSpinBox(); self.gen_length.setRange(4,128); self.gen_length.setValue(16)
        self.gen_words = QSpinBox(); self.gen_words.setRange(1,10); self.gen_words.setValue(4)
        self.gen_sep = QLineEdit(); self.gen_sep.setText("-")
        self.gen_use_lower = QCheckBox(); self.gen_use_lower.setChecked(True)
        self.gen_use_upper = QCheckBox(); self.gen_use_upper.setChecked(True)
        self.gen_use_digits = QCheckBox(); self.gen_use_digits.setChecked(True)
        self.gen_use_symbols = QCheckBox(); self.gen_use_symbols.setChecked(True)
        self.gen_exclude_amb = QCheckBox(); self.gen_exclude_amb.setChecked(True)
        self.gen_presets = QComboBox(); self.gen_presets.addItems(["Custom","16 strong","12 medium","8 short"])
        self.gen_presets.currentIndexChanged.connect(self._on_gen_preset)

        f_layout.addRow("Mode:", self.gen_mode)
        f_layout.addRow("Preset:", self.gen_presets)
        f_layout.addRow("Length:", self.gen_length)
        f_layout.addRow("Words (passphrase):", self.gen_words)
        f_layout.addRow("Separator:", self.gen_sep)
        f_layout.addRow("Use lowercase:", self.gen_use_lower)
        f_layout.addRow("Use uppercase:", self.gen_use_upper)
        f_layout.addRow("Use digits:", self.gen_use_digits)
        f_layout.addRow("Use symbols:", self.gen_use_symbols)
        f_layout.addRow("Exclude ambiguous:", self.gen_exclude_amb)
        self.gen_count = QSpinBox(); self.gen_count.setRange(1,20); self.gen_count.setValue(1)
        f_layout.addRow("Generate count:", self.gen_count)
        btn_h = QHBoxLayout()
        btn = QPushButton("Generate")
        btn.clicked.connect(self._on_generate)
        save_btn = QPushButton("Save generated to vault meta"); save_btn.clicked.connect(self._on_save_generated)
        btn_h.addWidget(btn); btn_h.addWidget(save_btn)
        f_layout.addRow(btn_h)
        form.setLayout(f_layout)

        layout.addWidget(form)
        out_group = QGroupBox("Generated Passwords")
        out_layout = QVBoxLayout()
        self.gen_output = QTextEdit(); self.gen_output.setReadOnly(True); self.gen_output.setFixedHeight(140)
        copy_btn = QPushButton("Copy & Clear in 15s")
        copy_btn.clicked.connect(self._on_copy_generated)
        out_layout.addWidget(self.gen_output)
        out_layout.addWidget(copy_btn)
        out_group.setLayout(out_layout)
        layout.addWidget(out_group)
        layout.addStretch()
        return w

    def _on_gen_preset(self, idx):
        if idx == 1:
            self.gen_length.setValue(16); self.gen_use_symbols.setChecked(True); self.gen_use_digits.setChecked(True)
        elif idx == 2:
            self.gen_length.setValue(12); self.gen_use_symbols.setChecked(False)
        elif idx == 3:
            self.gen_length.setValue(8); self.gen_use_symbols.setChecked(False)
        else:
            pass

    def _on_generate(self):
        mode = self.gen_mode.currentText()
        try:
            out = []
            for _ in range(self.gen_count.value()):
                if mode == 'Random':
                    pw = self.generator.generate(
                        length=self.gen_length.value(),
                        use_lower=self.gen_use_lower.isChecked(),
                        use_upper=self.gen_use_upper.isChecked(),
                        use_digits=self.gen_use_digits.isChecked(),
                        use_symbols=self.gen_use_symbols.isChecked(),
                        exclude_ambiguous=self.gen_exclude_amb.isChecked()
                    )
                elif mode == 'Passphrase':
                    pw = self.generator.generate_passphrase(words=self.gen_words.value(), separator=self.gen_sep.text() or '-')
                elif mode == 'Pronounceable':
                    pw = self.generator.generate_pronounceable(length=self.gen_length.value())
                else:
                    pw = self.generator.generate_pin(length=self.gen_length.value())
                out.append(pw)
            self.gen_output.setPlainText('\n'.join(out))
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _on_copy_generated(self):
        text = self.gen_output.toPlainText()
        if not text:
            return
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "Copied", f"Password(s) copied to clipboard for {CLIP_CLEAR_MS//1000} seconds.")
        QTimer.singleShot(CLIP_CLEAR_MS, self._clear_clipboard_if_matches)

    def _clear_clipboard_if_matches(self):
        QApplication.clipboard().clear()

    def _on_save_generated(self):
        text = self.gen_output.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "Empty", "No generated passwords to save")
            return
        if self.vault:
            meta = self.vault._plaintext_vault.setdefault('meta', {})
            saved = meta.setdefault('saved_passwords', [])
            for pw in text.splitlines():
                saved.append({"pw": pw, "saved_at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
            self.vault._write_encrypted()
            QMessageBox.information(self, "Saved", "Generated password(s) saved to vault meta (encrypted).")

    # ----- Strength Tab -----
    def _build_check_tab(self):
        w = QWidget(); layout = QVBoxLayout(w)
        grp = QGroupBox("Check Password Strength")
        g_layout = QVBoxLayout()
        self.check_input = QLineEdit(); self.check_input.setEchoMode(QLineEdit.Password)
        chk_btn = QPushButton("Check")
        chk_btn.clicked.connect(self._on_check)
        g_layout.addWidget(QLabel("Enter password to evaluate (hidden):"))
        g_layout.addWidget(self.check_input)
        g_layout.addWidget(chk_btn)
        grp.setLayout(g_layout)
        layout.addWidget(grp)
        out_group = QGroupBox("Analysis & Suggestions")
        out_layout = QVBoxLayout()
        self.check_out = QTextEdit(); self.check_out.setReadOnly(True)
        out_layout.addWidget(self.check_out)
        out_group.setLayout(out_layout)
        layout.addWidget(out_group)
        layout.addStretch()
        return w

    def _on_check(self):
        pwd = self.check_input.text()
        if not pwd:
            QMessageBox.warning(self, "Empty", "Please type a password to check.")
            return
        r = self.checker.score(pwd)
        txt = []
        txt.append(f"Entropy: {r['entropy_bits']} bits")
        txt.append(f"Strength: {r['strength']}")
        if r['issues']:
            txt.append("Issues: " + ', '.join(r['issues']))
        else:
            txt.append("No obvious issues detected.")
        txt.append('\nSuggestions:')
        alts = self.checker.suggest_alternatives(pwd, count=5)
        for i,a in enumerate(alts,1):
            txt.append(f"{i}. {a}  (strength: {self.checker.score(a)['strength']})")
        self.check_out.setPlainText('\n'.join(txt))

    # ----- Vault Tab -----
    def _build_vault_tab(self):
        w = QWidget(); layout = QVBoxLayout(w)
        toolbar = QHBoxLayout()
        self.search_input = QLineEdit(); self.search_input.setPlaceholderText('Search...')
        search_btn = QPushButton('Search'); search_btn.clicked.connect(self._on_search)
        add_btn = QPushButton('Add'); add_btn.clicked.connect(self._on_add_entry)
        edit_btn = QPushButton('Edit'); edit_btn.clicked.connect(self._on_edit_entry)
        del_btn = QPushButton('Delete'); del_btn.clicked.connect(self._on_delete_entry)
        copy_btn = QPushButton('Copy Password(s)'); copy_btn.clicked.connect(self._on_copy_password)
        reuse_btn = QPushButton('Find Reuse'); reuse_btn.clicked.connect(self._on_find_reuse)
        fav_btn = QPushButton('Toggle Favorite'); fav_btn.clicked.connect(self._on_toggle_favorite)
        show_pw_toggle = QPushButton('Show/Hide Passwords'); show_pw_toggle.setCheckable(True); show_pw_toggle.toggled.connect(self._on_toggle_show_password_preview)
        toolbar.addWidget(self.search_input); toolbar.addWidget(search_btn); toolbar.addWidget(add_btn);
        toolbar.addWidget(edit_btn); toolbar.addWidget(del_btn); toolbar.addWidget(copy_btn); toolbar.addWidget(reuse_btn)
        toolbar.addWidget(fav_btn); toolbar.addWidget(show_pw_toggle)
        layout.addLayout(toolbar)

        self.table = QTableWidget(0,6)
        self.table.setHorizontalHeaderLabels(['Label','Username','Last Updated','Tags','Fav','Strength'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setSortingEnabled(True)
        layout.addWidget(self.table)
        return w

    def _refresh_vault_table(self, rows: Optional[List[Dict[str,Any]]]=None):
        rows = rows if rows is not None else self.vault.list_entries()
        rows_sorted = sorted(rows, key=lambda e: (not bool(e.get('favorite', False)), e.get('label','').lower()))
        seen = {}
        reused_hashes = set()
        for e in rows_sorted:
            h = hashlib.sha256((e.get('password') or '').encode('utf-8')).hexdigest()
            if h in seen:
                reused_hashes.add(h)
            else:
                seen[h] = e['label']
        self.table.setRowCount(0)
        for e in rows_sorted:
            r = self.table.rowCount(); self.table.insertRow(r)
            self.table.setItem(r,0, QTableWidgetItem(e['label']))
            self.table.setItem(r,1, QTableWidgetItem(e.get('username','')))
            self.table.setItem(r,2, QTableWidgetItem(e.get('last_updated','')))
            self.table.setItem(r,3, QTableWidgetItem(','.join(e.get('tags',[]))))
            fav_item = QTableWidgetItem("★" if e.get('favorite') else "")
            fav_item.setFlags(fav_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(r,4, fav_item)
            sc = self.checker.score(e.get('password','') or '')
            strength_item = QTableWidgetItem(f"{sc['strength']} ({sc['entropy_bits']})")
            strength_item.setFlags(strength_item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(r,5, strength_item)
            h = hashlib.sha256((e.get('password') or '').encode('utf-8')).hexdigest()
            if h in reused_hashes:
                color = QColor(120, 30, 30)
            else:
                if sc['strength'] == 'weak':
                    color = QColor(120, 30, 30)
                elif sc['strength'] == 'moderate':
                    color = QColor(160, 120, 30)
                else:
                    color = QColor(30, 120, 40)
            for c in range(self.table.columnCount()):
                item = self.table.item(r,c)
                if item:
                    item.setBackground(color)
        self.table.repaint()

    def _on_search(self):
        q = self.search_input.text().strip()
        if not q:
            self._refresh_vault_table()
            return
        res = self.vault.search_entries(q)
        self._refresh_vault_table(res)

    def _on_add_entry(self):
        d = EntryEditor(parent=self, vault=self.vault, checker=self.checker)
        if d.exec() == QDialog.Accepted:
            label,username,password,notes,tags,favorite,cf, attaches = d.get_values()
            try:
                self.vault.add_entry(label,username,password,notes,tags,favorite,custom_fields=cf)
                e = self.vault.get_entry(label)
                if e and attaches:
                    e.setdefault('attachments', []).extend(attaches)
                    self.vault._write_encrypted()
                QMessageBox.information(self, "Added","Entry added")
                self._refresh_vault_table()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _selected_label(self) -> Optional[str]:
        rows = sorted(set(i.row() for i in self.table.selectedItems()))
        if not rows:
            return None
        return self.table.item(rows[0],0).text()

    def _selected_labels(self) -> List[str]:
        rows = sorted(set(i.row() for i in self.table.selectedItems()))
        labels = []
        for r in rows:
            labels.append(self.table.item(r,0).text())
        return labels

    def _on_edit_entry(self):
        label = self._selected_label()
        if not label:
            QMessageBox.warning(self, "Select","Select an entry first")
            return
        entry = self.vault.get_entry(label)
        d = EntryEditor(existing=entry, parent=self, vault=self.vault, checker=self.checker)
        if d.exec() == QDialog.Accepted:
            label,username,password,notes,tags,favorite,cf,attaches = d.get_values()
            try:
                self.vault.update_entry(label,username=username,password=password,notes=notes,tags=tags,favorite=favorite,custom_fields=cf)
                if attaches:
                    e = self.vault.get_entry(label)
                    e.setdefault('attachments', []).extend(attaches)
                    self.vault._write_encrypted()
                QMessageBox.information(self, "Updated","Entry updated")
                self._refresh_vault_table()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _on_delete_entry(self):
        label = self._selected_label()
        if not label:
            QMessageBox.warning(self, "Select","Select an entry first")
            return
        confirm = QMessageBox.question(self, "Confirm Delete", f"Delete '{label}'?", QMessageBox.Yes | QMessageBox.No)
        if confirm == QMessageBox.Yes:
            try:
                self.vault.delete_entry(label)
                QMessageBox.information(self, "Deleted","Entry deleted")
                self._refresh_vault_table()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _on_copy_password(self):
        labels = self._selected_labels()
        if not labels:
            QMessageBox.warning(self, "Select","Select one or more entries first")
            return
        out_lines = []
        for label in labels:
            entry = self.vault.get_entry(label)
            if not entry:
                continue
            out_lines.append(f"{label}\t{entry.get('username','')}\t{entry.get('password','')}")
        text = '\n'.join(out_lines)
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "Copied", f"Password(s) copied to clipboard for {CLIP_CLEAR_MS//1000} seconds.")
        QTimer.singleShot(CLIP_CLEAR_MS, self._clear_clipboard_if_matches)

    def _clear_clipboard_if_matches(self):
        QApplication.clipboard().clear()

    def _on_find_reuse(self):
        seen = {}
        reused = {}
        for e in self.vault.list_entries():
            h = hashlib.sha256(e.get('password','').encode('utf-8')).hexdigest()
            if h in seen:
                reused.setdefault(h, []).append(e['label'])
            else:
                seen[h] = e['label']
        groups = [labels for labels in reused.values() if len(labels) > 0]
        if not groups:
            QMessageBox.information(self, "No Reuse", "No reused passwords found")
            return
        msg = '\n'.join(','.join(g) for g in groups)
        QMessageBox.warning(self, "Reused Passwords", msg)

    def _on_toggle_favorite(self):
        label = self._selected_label()
        if not label:
            QMessageBox.warning(self, "Select","Select an entry first")
            return
        entry = self.vault.get_entry(label)
        if not entry:
            return
        newfav = not bool(entry.get('favorite', False))
        try:
            self.vault.update_entry(label, favorite=newfav)
            self._refresh_vault_table()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _on_toggle_show_password_preview(self, checked):
        if checked:
            txt = []
            for e in self.vault.list_entries():
                txt.append(f"{e['label']}\t{e.get('username','')}\t{e.get('password','')}")
            dlg = QDialog(self); dlg.setWindowTitle("Passwords (preview)"); dlg.resize(800,400)
            l = QVBoxLayout(dlg)
            te = QTextEdit(); te.setReadOnly(True); te.setPlainText('\n'.join(txt))
            l.addWidget(te)
            b = QDialogButtonBox(QDialogButtonBox.Ok); b.accepted.connect(dlg.accept)
            l.addWidget(b)
            dlg.exec()

    # ----- Tools Tab -----
    def _build_tools_tab(self):
        w = QWidget(); layout = QVBoxLayout(w)
        change_btn = QPushButton('Change Master Password'); change_btn.clicked.connect(self._on_change_master)
        export_btn = QPushButton('Export Encrypted Vault'); export_btn.clicked.connect(self._on_export)
        import_btn = QPushButton('Import Encrypted Vault'); import_btn.clicked.connect(self._on_import)
        backup_btn = QPushButton('Backup Vault (local)'); backup_btn.clicked.connect(self._on_backup)
        integrity_btn = QPushButton('Vault Integrity Check'); integrity_btn.clicked.connect(self._on_integrity_check)
        expiry_btn = QPushButton('Check for Old Entries'); expiry_btn.clicked.connect(self._on_expiry)
        weak_rep_btn = QPushButton('Weak Password Report'); weak_rep_btn.clicked.connect(self._report_weak)
        reuse_rep_btn = QPushButton('Reused Password Report'); reuse_rep_btn.clicked.connect(self._report_reused)
        lock_time_btn = QPushButton('Set Auto-lock Timeout'); lock_time_btn.clicked.connect(self._set_autolock)
        toggle_ro_btn = QPushButton('Toggle Read-Only Mode'); toggle_ro_btn.clicked.connect(self._toggle_readonly)
        theme_btn = QPushButton('Toggle Dark/Light Theme'); theme_btn.clicked.connect(self._toggle_theme)
        layout.addWidget(change_btn); layout.addWidget(export_btn); layout.addWidget(import_btn); layout.addWidget(backup_btn)
        layout.addWidget(integrity_btn); layout.addWidget(expiry_btn); layout.addWidget(weak_rep_btn); layout.addWidget(reuse_rep_btn)
        layout.addWidget(lock_time_btn); layout.addWidget(toggle_ro_btn); layout.addWidget(theme_btn)
        layout.addStretch()
        return w

    def _on_change_master(self):
        dlg = MasterPasswordDialog(creating=True, parent=self)
        if dlg.exec() != QDialog.Accepted:
            return
        new, confirm, new_q, new_a = dlg.get_passwords()
        score = self.checker.score(new)
        if not new or new != confirm or len(new) < MIN_MASTER_PW_LEN or score['strength'] == 'weak':
            QMessageBox.critical(self, 'Error','Passwords did not match or too weak')
            return
        try:
            self.vault.change_master_password(self.master_password, new)
            if new_q and new_a:
                sec_salt = os.urandom(12)
                hashed = hashlib.sha256(sec_salt + new_a.encode('utf-8')).hexdigest()
                self.vault.header['security'] = {
                    "question": new_q,
                    "salt": base64.urlsafe_b64encode(sec_salt).decode('utf-8'),
                    "answer_hash": hashed
                }
            self.master_password = new
            QMessageBox.information(self, 'Done', 'Master password changed')
        except Exception as e:
            QMessageBox.critical(self, 'Error', str(e))

    def _on_export(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Export Encrypted Vault', os.path.expanduser('~'), 'JSON Files (*.json)')
        if not path:
            return
        self.vault.export_encrypted_copy(path)
        QMessageBox.information(self, 'Exported', f'Exported to {path}')

    def _on_import(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Import Encrypted Vault', os.path.expanduser('~'), 'JSON Files (*.json)')
        if not path:
            return
        self.vault.import_encrypted_copy(path)
        QMessageBox.information(self, 'Imported', 'Imported vault. You may need to restart to fully re-open.')

    def _on_backup(self):
        out = self.vault.backup()
        QMessageBox.information(self, 'Backup', f'Backup created at {out}')

    def _on_integrity_check(self):
        ok = self.vault.integrity_check()
        if ok:
            QMessageBox.information(self, 'Integrity', 'Vault integrity OK (decryptable).')
        else:
            QMessageBox.warning(self, 'Integrity', 'Vault integrity check failed or not decryptable with current key.')

    def _on_expiry(self):
        days, ok = QInputDialog.getInt(self, 'Expiry Check', 'Consider older than how many days?', 365, 1, 10000)
        if not ok:
            return
        threshold = datetime.datetime.utcnow() - datetime.timedelta(days=days)
        outdated = []
        for e in self.vault.list_entries():
            last = e.get('last_updated', e.get('created_at'))
            try:
                last_dt = datetime.datetime.fromisoformat(last.replace('Z', '+00:00'))
            except Exception:
                continue
            if last_dt < threshold:
                outdated.append((e['label'], last))
        if not outdated:
            QMessageBox.information(self, 'All Good', 'No entries older than threshold')
            return
        msg = '\n'.join([f"{l} (last updated {t})" for l,t in outdated])
        QMessageBox.warning(self, 'Outdated Entries', msg)

    def _report_weak(self):
        weak = []
        for e in self.vault.list_entries():
            sc = self.checker.score(e.get('password',''))
            if sc['strength'] == 'weak' or 'too_short' in sc['issues'] or 'low_entropy' in sc['issues']:
                weak.append((e['label'], sc))
        if not weak:
            QMessageBox.information(self, "Weak Report", "No weak passwords detected.")
            return
        txt = '\n'.join([f"{l}: {s['strength']} ({s['entropy_bits']} bits) issues={','.join(s['issues'])}" for l,s in weak])
        dlg = QDialog(self); dlg.setWindowTitle("Weak Password Report"); dlg.resize(700,400)
        l = QVBoxLayout(dlg); te = QTextEdit(); te.setPlainText(txt); te.setReadOnly(True); l.addWidget(te)
        b = QDialogButtonBox(QDialogButtonBox.Ok); b.accepted.connect(dlg.accept); l.addWidget(b); dlg.exec()

    def _report_reused(self):
        seen = {}
        reused = {}
        for e in self.vault.list_entries():
            h = hashlib.sha256(e.get('password','').encode('utf-8')).hexdigest()
            if h in seen:
                reused.setdefault(h, [seen[h]]).append(e['label'])
            else:
                seen[h] = e['label']
        groups = [labels for labels in reused.values() if len(labels) > 1]
        if not groups:
            QMessageBox.information(self, "No Reuse", "No reused passwords found")
            return
        txt = '\n'.join(','.join(g) for g in groups)
        dlg = QDialog(self); dlg.setWindowTitle("Reused Passwords"); dlg.resize(700,400)
        l = QVBoxLayout(dlg); te = QTextEdit(); te.setPlainText(txt); te.setReadOnly(True); l.addWidget(te)
        b = QDialogButtonBox(QDialogButtonBox.Ok); b.accepted.connect(dlg.accept); l.addWidget(b); dlg.exec()

    def _set_autolock(self):
        minutes, ok = QInputDialog.getInt(self, 'Auto-lock', 'Auto-lock after (minutes):', self.auto_lock_ms // 60000, 0, 60*24)
        if not ok:
            return
        self.auto_lock_ms = minutes * 60 * 1000
        self.auto_lock_timer.setInterval(self.auto_lock_ms)
        QMessageBox.information(self, "Auto-lock", f"Auto-lock set to {minutes} minute(s).")

    def _toggle_readonly(self):
        self.vault.read_only = not self.vault.read_only
        state = "enabled" if self.vault.read_only else "disabled"
        QMessageBox.information(self, "Read-Only", f"Vault read-only mode {state}.")

    def _toggle_theme(self):
        if self.theme == 'dark':
            self.theme = 'light'
            self.setStyleSheet(LIGHT_QSS)
        else:
            self.theme = 'dark'
            self.setStyleSheet(DARK_QSS)

    # Dashboard tab
    def _build_dashboard_tab(self):
        w = QWidget(); layout = QVBoxLayout(w)
        stats_btn = QPushButton("Refresh Stats"); stats_btn.clicked.connect(self._refresh_stats)
        self.stats_area = QTextEdit(); self.stats_area.setReadOnly(True)
        layout.addWidget(stats_btn); layout.addWidget(self.stats_area)
        return w

    def _refresh_stats(self):
        entries = self.vault.list_entries()
        cnt = len(entries)
        ent_sum = 0.0
        reused_count = 0
        seen = {}
        tag_counts = {}
        for e in entries:
            sc = self.checker.score(e.get('password',''))
            ent_sum += sc['entropy_bits']
            h = hashlib.sha256(e.get('password','').encode('utf-8')).hexdigest()
            if h in seen:
                reused_count += 1
            else:
                seen[h] = e['label']
            for t in e.get('tags', []):
                tag_counts[t] = tag_counts.get(t,0) + 1
        avg_ent = (ent_sum / cnt) if cnt else 0.0
        health_score = max(0, 100 - int((max(0,40-avg_ent))*2) - reused_count*5)
        txt = [
            f"Entries: {cnt}",
            f"Reused passwords (approx count): {reused_count}",
            f"Average entropy: {avg_ent:.2f} bits",
            f"Vault health score (0-100): {health_score}",
            "",
            "Top tags:"
        ]
        for t,n in sorted(tag_counts.items(), key=lambda x: -x[1])[:20]:
            txt.append(f"{t}: {n}")
        self.stats_area.setPlainText('\n'.join(txt))

# ------------------ Entry Point ------------------
def main():
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon())
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()

