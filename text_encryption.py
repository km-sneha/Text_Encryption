import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Text Encryption Tool")
        self.root.geometry("600x500")
        self.root.resizable(False, False)
        self.root.configure(bg="#f0f4f8")

        # Hook close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Heading
        title = tk.Label(root, text="Secure Text Encryption", font=("Arial", 20, "bold"), bg="#f0f4f8", fg="#2c3e50")
        title.pack(pady=20)

        # Input
        self.input_label = tk.Label(root, text="Enter Text:", bg="#f0f4f8", font=("Arial", 12))
        self.input_label.pack()
        self.input_text = tk.Text(root, height=5, width=60)
        self.input_text.pack(pady=10)

        # Dropdown
        self.algo_label = tk.Label(root, text="Select Encryption Algorithm:", bg="#f0f4f8", font=("Arial", 12))
        self.algo_label.pack()
        self.algo_choice = ttk.Combobox(root, values=["AES", "DES", "RSA"], state="readonly")
        self.algo_choice.pack(pady=5)
        self.algo_choice.set("AES")

        # Buttons
        self.encrypt_btn = tk.Button(root, text="Encrypt", command=self.encrypt_text, bg="#3498db", fg="white", width=15)
        self.encrypt_btn.pack(pady=10)

        self.decrypt_btn = tk.Button(root, text="Decrypt", command=self.decrypt_text, bg="#2ecc71", fg="white", width=15)
        self.decrypt_btn.pack(pady=5)

        # Output
        self.output_label = tk.Label(root, text="Output:", bg="#f0f4f8", font=("Arial", 12))
        self.output_label.pack()
        self.output_text = tk.Text(root, height=6, width=60, state='normal')
        self.output_text.pack(pady=10)

        # Status Message
        self.status_message = tk.Label(root, text="", font=("Arial", 10, "italic"), fg="#7f8c8d", bg="#f0f4f8")
        self.status_message.pack()

        # Internal storage
        self.last_encrypted = None
        self.key = None
        self.rsa_key_pair = None

    def encrypt_text(self):
        text = self.input_text.get("1.0", tk.END).strip()
        algo = self.algo_choice.get()
        if not text:
            messagebox.showerror("Error", "Please enter some text to encrypt.")
            return

        self.status_message.config(text="Encrypting... Please wait.")
        self.root.update()

        try:
            if algo == "AES":
                self.key = get_random_bytes(16)
                cipher = AES.new(self.key, AES.MODE_EAX)
                ciphertext, tag = cipher.encrypt_and_digest(text.encode())
                self.last_encrypted = base64.b64encode(cipher.nonce + tag + ciphertext).decode()

            elif algo == "DES":
                self.key = get_random_bytes(8)
                cipher = DES.new(self.key, DES.MODE_ECB)
                pad_len = 8 - len(text) % 8
                padded_text = text + chr(pad_len) * pad_len
                ciphertext = cipher.encrypt(padded_text.encode())
                self.last_encrypted = base64.b64encode(ciphertext).decode()

            elif algo == "RSA":
                self.rsa_key_pair = RSA.generate(2048)
                public_key = self.rsa_key_pair.publickey()
                cipher = PKCS1_OAEP.new(public_key)
                ciphertext = cipher.encrypt(text.encode())
                self.last_encrypted = base64.b64encode(ciphertext).decode()

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, self.last_encrypted)
            self.status_message.config(text="Encryption completed successfully.")
            messagebox.showinfo("Success", "Text encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.status_message.config(text="Encryption failed.")

    def decrypt_text(self):
        if not self.last_encrypted:
            messagebox.showerror("Error", "No encrypted text to decrypt.")
            return

        self.status_message.config(text="Decrypting... Please wait.")
        self.root.update()

        algo = self.algo_choice.get()
        try:
            encrypted_data = base64.b64decode(self.last_encrypted.encode())

            if algo == "AES":
                nonce = encrypted_data[:16]
                tag = encrypted_data[16:32]
                ciphertext = encrypted_data[32:]
                cipher = AES.new(self.key, AES.MODE_EAX, nonce)
                decrypted = cipher.decrypt_and_verify(ciphertext, tag).decode()

            elif algo == "DES":
                cipher = DES.new(self.key, DES.MODE_ECB)
                decrypted = cipher.decrypt(encrypted_data).decode()
                pad_len = ord(decrypted[-1])
                decrypted = decrypted[:-pad_len]

            elif algo == "RSA":
                cipher = PKCS1_OAEP.new(self.rsa_key_pair)
                decrypted = cipher.decrypt(encrypted_data).decode()

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decrypted)
            self.status_message.config(text="Decryption completed successfully.")
            messagebox.showinfo("Success", "Text decrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.status_message.config(text="Decryption failed.")

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to exit?"):
            messagebox.showinfo("Thank You", "Thank you for using the Text Encryption Tool! Stay secure.")
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
