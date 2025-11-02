# password_hasher_app.py
# Requires: customtkinter, bcrypt
# pip install customtkinter bcrypt

import customtkinter as ctk
import bcrypt
import csv
import os
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, filedialog

# ---------- App configuration ----------
ctk.set_appearance_mode("dark")  # "dark" or "light"
ctk.set_default_color_theme("dark-blue")  # builtin themes: "blue", "green", "dark-blue"

APP_TITLE = "Secure Password Hasher — bcrypt"
WINDOW_SIZE = "800x500"
DEFAULT_ROUNDS = 12  # bcrypt cost default

# ---------- Helpers ----------
def hash_password(password: str, rounds: int) -> bytes:
    pw_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(pw_bytes, salt)
    return hashed  # bytes

def verify_password(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except ValueError:
        return False

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

# ---------- Main App ----------
class PasswordHasherApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(WINDOW_SIZE)
        self.resizable(False, False)

        # Styles
        padding = 18

        # Main frame
        self.grid_columnconfigure(0, weight=1)
        container = ctk.CTkFrame(self, corner_radius=16, fg_color="#1f2227")
        container.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        container.grid_columnconfigure((0,1), weight=1)

        # Left side — Inputs
        left = ctk.CTkFrame(container, corner_radius=12)
        left.grid(row=0, column=0, padx=(padding, 8), pady=padding, sticky="nsew")
        left.grid_rowconfigure((0,1,2,3), weight=0)
        left.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(left, text="Enter password", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=12, pady=(12,6), sticky="w")
        self.entry_password = ctk.CTkEntry(left, show="*", placeholder_text="Type password here")
        self.entry_password.grid(row=1, column=0, padx=12, pady=(0,12), sticky="ew")

        ctk.CTkLabel(left, text="Cost (rounds)", font=ctk.CTkFont(size=12)).grid(row=2, column=0, padx=12, pady=(6,4), sticky="w")
        self.rounds_slider = ctk.CTkSlider(left, from_=8, to=16, number_of_steps=8, command=self._on_rounds_change)
        self.rounds_slider.set(DEFAULT_ROUNDS)
        self.rounds_slider.grid(row=3, column=0, padx=12, pady=(0,10), sticky="ew")
        self.rounds_label = ctk.CTkLabel(left, text=f"Rounds: {DEFAULT_ROUNDS}")
        self.rounds_label.grid(row=4, column=0, padx=12, pady=(0,12), sticky="w")

        self.generate_btn = ctk.CTkButton(left, text="Generate Hash", command=self.generate_hash, width=160, corner_radius=12)
        self.generate_btn.grid(row=5, column=0, padx=12, pady=(6,12), sticky="w")

        # Right side — Verification & Output
        right = ctk.CTkFrame(container, corner_radius=12)
        right.grid(row=0, column=1, padx=(8, padding), pady=padding, sticky="nsew")
        right.grid_rowconfigure((0,1,2,3,4), weight=0)

        ctk.CTkLabel(right, text="Hash output", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=12, pady=(12,6), sticky="w")
        self.hash_text = ctk.CTkTextbox(right, height=120, wrap="word")
        self.hash_text.grid(row=1, column=0, padx=12, pady=(0,12), sticky="ew")
        self.hash_text.configure(state="disabled")

        copy_frame = ctk.CTkFrame(right, corner_radius=8)
        copy_frame.grid(row=2, column=0, padx=12, pady=(0,12), sticky="ew")
        copy_frame.grid_columnconfigure((0,1,2), weight=1)
        self.copy_btn = ctk.CTkButton(copy_frame, text="Copy Hash", command=self.copy_hash, corner_radius=10)
        self.copy_btn.grid(row=0, column=0, padx=6, pady=6)
        self.save_btn = ctk.CTkButton(copy_frame, text="Save Hash", command=self.save_hash, corner_radius=10)
        self.save_btn.grid(row=0, column=1, padx=6, pady=6)
        self.clear_btn = ctk.CTkButton(copy_frame, text="Clear", command=self.clear_all, corner_radius=10)
        self.clear_btn.grid(row=0, column=2, padx=6, pady=6)

        # Verification UI
        ctk.CTkLabel(right, text="Verify password against hash", font=ctk.CTkFont(size=14)).grid(row=3, column=0, padx=12, pady=(6,6), sticky="w")
        self.entry_verify = ctk.CTkEntry(right, show="*", placeholder_text="Type password to verify")
        self.entry_verify.grid(row=4, column=0, padx=12, pady=(0,8), sticky="ew")

        verify_frame = ctk.CTkFrame(right, corner_radius=6)
        verify_frame.grid(row=5, column=0, padx=12, pady=(0,12), sticky="ew")
        verify_frame.grid_columnconfigure((0,1), weight=1)
        self.verify_btn = ctk.CTkButton(verify_frame, text="Verify", command=self.verify_hash, corner_radius=10)
        self.verify_btn.grid(row=0, column=0, padx=6, pady=6)
        self.result_label = ctk.CTkLabel(verify_frame, text="", anchor="w")
        self.result_label.grid(row=0, column=1, padx=6, pady=6, sticky="w")

        # Footer / credits
        footer = ctk.CTkLabel(self, text="Made with — Esraa Codes", font=ctk.CTkFont(size=10))
        footer.place(relx=0.5, rely=0.97, anchor="s")

        # internal state
        self.current_hash = None

    # ---------- callbacks ----------
    def _on_rounds_change(self, val):
        rounds = int(round(val))
        self.rounds_label.configure(text=f"Rounds: {rounds}")

    def generate_hash(self):
        pwd = self.entry_password.get()
        if not pwd:
            messagebox.showwarning("Missing password", "Please enter a password to hash.")
            return
        rounds = int(round(self.rounds_slider.get()))
        try:
            hashed = hash_password(pwd, rounds)
            # display as utf-8 string
            hashed_str = hashed.decode("utf-8")
            self.current_hash = hashed_str
            self._set_hash_text(hashed_str)
            messagebox.showinfo("Done", "Hash generated successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate hash:\n{e}")

    def _set_hash_text(self, text: str):
        self.hash_text.configure(state="normal")
        self.hash_text.delete("1.0", "end")
        self.hash_text.insert("1.0", text)
        self.hash_text.configure(state="disabled")

    def copy_hash(self):
        if not self.current_hash:
            messagebox.showwarning("No hash", "No hash to copy. Generate first.")
            return
        self.clipboard_clear()
        self.clipboard_append(self.current_hash)
        messagebox.showinfo("Copied", "Hash copied to clipboard.")

    def save_hash(self):
        if not self.current_hash:
            messagebox.showwarning("No hash", "No hash to save. Generate first.")
            return
        # default folder
        default_dir = os.path.join(os.path.expanduser("~"), "password_hashes")
        ensure_dir(default_dir)
        filename = filedialog.asksaveasfilename(initialdir=default_dir,
                                                defaultextension=".csv",
                                                filetypes=[("CSV files","*.csv")],
                                                title="Save hash as")
        if not filename:
            return
        try:
            is_new = not os.path.exists(filename)
            with open(filename, "a", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                if is_new:
                    writer.writerow(["timestamp_utc", "hash", "rounds"])
                writer.writerow([datetime.utcnow().isoformat(), self.current_hash, int(round(self.rounds_slider.get()))])
            messagebox.showinfo("Saved", f"Hash saved to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Save error", f"Could not save file:\n{e}")

    def verify_hash(self):
        if not self.current_hash:
            messagebox.showwarning("No hash", "No hash to verify against. Generate first.")
            return
        verify_pwd = self.entry_verify.get()
        if not verify_pwd:
            messagebox.showwarning("Missing password", "Please enter a password to verify.")
            return
        try:
            ok = verify_password(verify_pwd, self.current_hash.encode("utf-8"))
            if ok:
                self.result_label.configure(text="Match", text_color="green")
            else:
                self.result_label.configure(text="No match", text_color="red")
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed:\n{e}")

    def clear_all(self):
        self.entry_password.delete(0, tk.END)
        self.entry_verify.delete(0, tk.END)
        self._set_hash_text("")
        self.current_hash = None
        self.result_label.configure(text="")

# ---------- run ----------
if __name__ == "__main__":
    app = PasswordHasherApp()
    app.mainloop()
