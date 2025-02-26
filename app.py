import streamlit as st
from PIL import Image
from stegano import lsb
from cryptography.fernet import Fernet
import bcrypt
import os

# Generate a key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Function to hash password
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Function to verify password
def verify_password(stored_hash, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_hash.encode())

# Function to encrypt a message
def encrypt_message(message):
    return cipher_suite.encrypt(message.encode()).decode()

# Function to decrypt a message
def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message.encode()).decode()

# Streamlit UI
st.title("🔐 Steganography Tool")
task = st.radio("Choose an option:", ["Encrypt Message", "Decrypt Message"])

if task == "Encrypt Message":
    uploaded_image = st.file_uploader("Upload an image", type=["png", "jpg"])
    secret_message = st.text_area("Enter the message to hide")
    password = st.text_input("Enter password", type="password")

    if st.button("Encrypt & Save Image"):
        if uploaded_image and secret_message and password:
            try:
                img = Image.open(uploaded_image)
                hashed_password = hash_password(password)
                encrypted_msg = encrypt_message(secret_message)
                encoded_img = lsb.hide(img, hashed_password + encrypted_msg)
                encoded_img.save("encoded_image.png")
                
                with open("encoded_image.png", "rb") as file:
                    btn = st.download_button(
                        label="Download Encoded Image",
                        data=file,
                        file_name="encoded_image.png",
                        mime="image/png"
                    )
            except Exception as e:
                st.error(f"Error: {e}")
        else:
            st.warning("Please provide an image, message, and password.")

elif task == "Decrypt Message":
    uploaded_image = st.file_uploader("Upload an encoded image", type=["png", "jpg"])
    password = st.text_input("Enter password", type="password")

    if st.button("Decrypt Message"):
        if uploaded_image and password:
            try:
                img = Image.open(uploaded_image)
                hidden_data = lsb.reveal(img)
                stored_hash = hidden_data[:60]  # Extract hashed password
                encrypted_msg = hidden_data[60:]  # Extract encrypted message
                
                if verify_password(stored_hash, password):
                    decrypted_message = decrypt_message(encrypted_msg)
                    st.success("Message successfully decrypted:")
                    st.write(decrypted_message)
                else:
                    st.error("Incorrect password! Try again.")
            except Exception as e:
                st.error("Failed to decode the image. Ensure it's correctly encoded.")
        else:
            st.warning("Please upload an encoded image and enter the password.")
