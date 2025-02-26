import os
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from stegano import lsb
from cryptography.fernet import Fernet
import bcrypt

# Generate a key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

def show_main_menu():
    encrypt_frame.pack_forget()
    decrypt_frame.pack_forget()
    main_menu.pack()

def show_encrypt_section():
    main_menu.pack_forget()
    encrypt_frame.pack()

def show_decrypt_section():
    main_menu.pack_forget()
    decrypt_frame.pack()

def select_image(entry_field):
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg")])
    entry_field.delete(0, tk.END)
    entry_field.insert(0, file_path)

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(stored_hash, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_hash.encode())

def encrypt_message(message):
    return cipher_suite.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message.encode()).decode()

def encrypt_image():
    img_path = encrypt_img_path.get()
    message = encrypt_message_text.get("1.0", tk.END).strip()
    password = encrypt_password.get()
    if not img_path or not message or not password:
        messagebox.showerror("Error", "All fields are required!")
        return
    try:
        hashed_password = hash_password(password)
        encrypted_msg = encrypt_message(message)
        img = Image.open(img_path)
        encoded_img = lsb.hide(img_path, hashed_password + encrypted_msg)
        output_path = "encoded_image.png"
        encoded_img.save(output_path)
        messagebox.showinfo("Success", "Image encoded successfully!")
        download_button.pack()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to encode image: {e}")

def download_encoded_image():
    save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    if save_path:
        os.rename("encoded_image.png", save_path)
        messagebox.showinfo("Success", "Image saved successfully!")

def decrypt_image():
    img_path = decrypt_img_path.get()
    password = decrypt_password.get()
    if not img_path or not password:
        messagebox.showerror("Error", "All fields are required!")
        return
    try:
        hidden_data = lsb.reveal(img_path)
        stored_hash = hidden_data[:60]  # Extract hashed password
        encrypted_msg = hidden_data[60:]  # Extract encrypted message
        if verify_password(stored_hash, password):
            decrypted_message.set(decrypt_message(encrypted_msg))
        else:
            decrypted_message.set("Incorrect password!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decode image: {e}")

# Function to add hover effects
def add_hover_effects(button):
    button.bind("<Enter>", lambda event: button.config(bg="lightblue"))
    button.bind("<Leave>", lambda event: button.config(bg="SystemButtonFace"))

root = tk.Tk()
root.title("Steganography Tool")
root.geometry("500x550")
footer = tk.Label(root, text="Developed by Nikhil K.", font=("Arial", 10), fg="gray")
footer.pack(side="bottom", pady=10)


main_menu = tk.Frame(root)
tk.Label(main_menu, text="Steganography Tool", font=("Times New Roman", 25)).pack()
steg_img = Image.open("steganography_img.png")
steg_img = steg_img.resize((350, 300))
steg_photo = ImageTk.PhotoImage(steg_img)
steg_label = tk.Label(main_menu, image=steg_photo)
steg_label.pack()

encrypt_button = tk.Button(main_menu, text="🔏 Encrypt", command=show_encrypt_section, font=("Georgia", 14), width=15, height=2)
decrypt_button = tk.Button(main_menu, text="🔓 Decrypt", command=show_decrypt_section, font=("Georgia", 14), width=15, height=2)
encrypt_button.pack(pady=3)
decrypt_button.pack(pady=3)

# Apply hover effect
add_hover_effects(encrypt_button)
add_hover_effects(decrypt_button)

main_menu.pack()

encrypt_frame = tk.Frame(root)
tk.Label(encrypt_frame, text="Encrypt Image", font=("Comic Sans MS", 17, "bold")).pack(pady=10)
tk.Label(encrypt_frame, text="Image Path:", font=("Verdana", 11)).pack()
encrypt_img_path = tk.Entry(encrypt_frame, width=40, font=("Arial", 10))
encrypt_img_path.pack(pady=5)

browse_button_enc = tk.Button(encrypt_frame, text="📁 Browse Image", command=lambda: select_image(encrypt_img_path), font=("Arial", 13), width=14,height=1)
browse_button_enc.pack(pady=5)
add_hover_effects(browse_button_enc)

tk.Label(encrypt_frame, text="🔑Password/Secret Key :", font=("Verdana", 11)).pack()
encrypt_password = tk.Entry(encrypt_frame, show="*", width=40)
encrypt_password.pack(pady=1)
def toggle_encrypt_password():
    if encrypt_password_toggle_var.get():
        encrypt_password.config(show="")
    else:
        encrypt_password.config(show="*")

encrypt_password_toggle_var = tk.BooleanVar()
encrypt_password_toggle = tk.Checkbutton(
    encrypt_frame, text="👁 Show Password", variable=encrypt_password_toggle_var,
    command=toggle_encrypt_password
)
encrypt_password_toggle.pack()

tk.Label(encrypt_frame, text="✉Message:", font=("Verdana", 11)).pack()
encrypt_message_text = tk.Text(encrypt_frame, height=4, width=40)
encrypt_message_text.pack(pady=5)

encrypt_action_button = tk.Button(encrypt_frame, text="🔏 Encrypt", command=encrypt_image, font=("Arial", 13, "bold"), width=15, height=2)
encrypt_action_button.pack(pady=5)
add_hover_effects(encrypt_action_button)

download_button = tk.Button(encrypt_frame, text="📥 Download Encoded Image", command=download_encoded_image, font=("Arial", 12), width=23, height=1)
add_hover_effects(download_button)

back_button_enc = tk.Button(encrypt_frame, text="◀ Back", command=show_main_menu, font=("Tahoma", 13), width=9, height=1)
back_button_enc.pack(pady=5)
add_hover_effects(back_button_enc)

decrypt_frame = tk.Frame(root)
tk.Label(decrypt_frame, text="Decrypt Image", font=("Comic Sans MS", 17, "bold")).pack(pady=10)
tk.Label(decrypt_frame, text="Image Path:", font=("Verdana", 11)).pack()
decrypt_img_path = tk.Entry(decrypt_frame, width=40, font=("Arial", 10))
decrypt_img_path.pack()

browse_button_dec = tk.Button(decrypt_frame, text="📁 Browse Image", command=lambda: select_image(decrypt_img_path), font=("Arial", 12), width=14,height=1)
browse_button_dec.pack(pady=7)
add_hover_effects(browse_button_dec)

tk.Label(decrypt_frame, text="🔑Password/Secret Key :", font=("Verdana", 11)).pack()
decrypt_password = tk.Entry(decrypt_frame, show="*", width=40)
decrypt_password.pack()
def toggle_decrypt_password():
    if decrypt_password_toggle_var.get():
        decrypt_password.config(show="")
    else:
        decrypt_password.config(show="*")

decrypt_password_toggle_var = tk.BooleanVar()
decrypt_password_toggle = tk.Checkbutton(
    decrypt_frame, text="👁 Show Password", variable=decrypt_password_toggle_var,
    command=toggle_decrypt_password
)
decrypt_password_toggle.pack()


decrypt_action_button = tk.Button(decrypt_frame, text="🔓 Decrypt", command=decrypt_image, font=("Arial", 12, "bold"), width=15, height=2)
decrypt_action_button.pack(pady=5)
add_hover_effects(decrypt_action_button)

decrypted_message = tk.StringVar()
tk.Label(decrypt_frame, textvariable=decrypted_message, wraplength=400, font=("Arial", 12)).pack(pady=5)

back_button_dec = tk.Button(decrypt_frame, text="◀ Back", command=show_main_menu, font=("Tahoma", 12), width=8, height=1)
back_button_dec.pack(pady=5)
add_hover_effects(back_button_dec)

root.mainloop()
