import os
import streamlit as st
from PIL import Image
from stegano import lsb
from cryptography.fernet import Fernet
import bcrypt

# Generate and store encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(stored_hash, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_hash.encode())

def encrypt_message(message):
    return cipher_suite.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message.encode()).decode()

st.title("Steganography Tool - Encrypt & Decrypt Messages")
option = st.radio("Choose an option:", ("Encrypt", "Decrypt"))

if option == "Encrypt":
    uploaded_file = st.file_uploader("Upload an image", type=["png", "jpg"])
    message = st.text_area("Enter the message to hide")
    password = st.text_input("Enter password", type="password")
    if st.button("Encrypt Image"):
        if uploaded_file and message and password:
            try:
                img = Image.open(uploaded_file)
                hashed_password = hash_password(password)
                encrypted_msg = encrypt_message(message)
                encoded_img = lsb.hide(img, hashed_password + encrypted_msg)
                encoded_img.save("encoded_image.png")
                st.success("Image encoded successfully!")
                with open("encoded_image.png", "rb") as file:
                    st.download_button("Download Encoded Image", file, file_name="encoded_image.png", mime="image/png")
            except Exception as e:
                st.error(f"Failed to encode image: {e}")
        else:
            st.error("All fields are required!")

elif option == "Decrypt":
    uploaded_file = st.file_uploader("Upload an encoded image", type=["png"])
    password = st.text_input("Enter password", type="password")
    if st.button("Decrypt Image"):
        if uploaded_file and password:
            try:
                img = Image.open(uploaded_file)
                hidden_data = lsb.reveal(img)
                stored_hash = hidden_data[:60]
                encrypted_msg = hidden_data[60:]
                if verify_password(stored_hash, password):
                    decrypted_text = decrypt_message(encrypted_msg)
                    st.success("Decryption Successful!")
                    st.text_area("Decrypted Message:", decrypted_text, height=100)
                else:
                    st.error("Incorrect password!")
            except Exception as e:
                st.error("Failed to decode the image. Ensure it's correctly encoded.")
        else:
            st.error("All fields are required!")
