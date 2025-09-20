import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

def main():
    try:
        # Load exported vault
        path = input("Vault file path (e.g., vault_export.json): ").strip()
        with open(path, "r") as f:
            vault = json.load(f)

        salt = base64.urlsafe_b64decode(vault["salt"])
        iterations = vault["kdf_iterations"]
        data_b64 = vault["data"]

        # Master password
        master_password = input("Enter master password: ").encode("utf-8")

        # Derive key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password))

        # Decrypt
        fernet = Fernet(key)
        decrypted = fernet.decrypt(base64.urlsafe_b64decode(data_b64))
        plaintext_vault = json.loads(decrypted.decode("utf-8"))

        # Print vault info
        entries = plaintext_vault.get("entries", {})
        if not entries:
            print("\nVault is empty.\n")
        else:
            print("\nVault Entries:\n")
            for label, e in entries.items():
                print(f"Label: {label}")
                print(f"  Username: {e.get('username','')}")
                print(f"  Password: {e.get('password','')}")
                print(f"  Tags: {', '.join(e.get('tags',[]))}")
                print(f"  Notes: {e.get('notes','')}")
                print(f"  Last Updated: {e.get('last_updated','')}")
                print("-" * 40)

        input("Press Enter to exit...")

    except InvalidToken:
        print("ERROR: Wrong master password or corrupted vault!")
        input("Press Enter to exit...")
    except FileNotFoundError:
        print("ERROR: Vault file not found!")
        input("Press Enter to exit...")
    except Exception as e:
        print(f"ERROR: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
