import os
import streamlit as st
from PIL import Image
from stegano import lsb
from cryptography.fernet import Fernet
import bcrypt

# Generate a key for encryption
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

st.title("🔐 Steganography Tool - Encrypt & Decrypt Messages in Images")
menu = ["Home", "Encrypt", "Decrypt"]
choice = st.sidebar.selectbox("Select an option", menu)

if choice == "Encrypt":
    st.subheader("🔏 Encrypt a Message into an Image")
    uploaded_image = st.file_uploader("Upload an Image", type=["png", "jpg", "jpeg"])
    secret_message = st.text_area("Enter your secret message")
    password = st.text_input("Enter a password", type="password")
    
    if st.button("Encrypt & Save Image"):
        if uploaded_image and secret_message and password:
            img = Image.open(uploaded_image)
            hashed_password = hash_password(password)
            encrypted_msg = encrypt_message(secret_message)
            encoded_img = lsb.hide(img, hashed_password + encrypted_msg)
            
            output_path = "encoded_image.png"
            encoded_img.save(output_path)
            st.success("Image successfully encoded!")
            with open(output_path, "rb") as file:
                st.download_button(label="📥 Download Encoded Image", data=file, file_name="encoded_image.png", mime="image/png")
        else:
            st.error("Please provide an image, message, and password!")

elif choice == "Decrypt":
    st.subheader("🔓 Decrypt a Message from an Image")
    uploaded_encoded_image = st.file_uploader("Upload an Encoded Image", type=["png", "jpg", "jpeg"])
    password = st.text_input("Enter the password", type="password")
    
    if st.button("Decrypt Message"):
        if uploaded_encoded_image and password:
            img = Image.open(uploaded_encoded_image)
            try:
                hidden_data = lsb.reveal(img)
                stored_hash, encrypted_msg = hidden_data[:60], hidden_data[60:]
                
                if verify_password(stored_hash, password):
                    decrypted_msg = decrypt_message(encrypted_msg)
                    st.success("Decryption successful! Here's the hidden message:")
                    st.info(decrypted_msg)
                else:
                    st.error("Incorrect password!")
            except Exception as e:
                st.error("Failed to decode the image. Ensure it's correctly encoded.")
        else:
            st.error("Please upload an encoded image and enter the password!")
