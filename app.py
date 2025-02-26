import os
import streamlit as st
from PIL import Image
from stegano import lsb
from cryptography.fernet import Fernet
import bcrypt

# Generate encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Streamlit UI
st.title("🛡️ Steganography Tool")

# Sidebar for navigation
menu = st.sidebar.radio("Navigation", ["🔏 Encrypt Image", "🔓 Decrypt Image"])

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(stored_hash, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_hash.encode())

def encrypt_message(message):
    return cipher_suite.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message.encode()).decode()

if menu == "🔏 Encrypt Image":
    st.header("Encrypt a Message Inside an Image")

    img_file = st.file_uploader("Upload an Image", type=["png", "jpg"])
    password = st.text_input("🔑 Enter Password", type="password")
    message = st.text_area("✉ Enter Secret Message")

    if st.button("🔏 Encrypt & Save Image"):
        if img_file and password and message:
            try:
                hashed_password = hash_password(password)
                encrypted_msg = encrypt_message(message)
                
                # Save uploaded image temporarily
                temp_image_path = "temp_image.png"
                image = Image.open(img_file)
                image.save(temp_image_path)

                # Encode message
                encoded_img = lsb.hide(temp_image_path, hashed_password + encrypted_msg)
                encoded_img.save("encoded_image.png")

                st.success("✅ Image encoded successfully!")
                with open("encoded_image.png", "rb") as file:
                    st.download_button("📥 Download Encoded Image", file, file_name="encoded_image.png")
            except Exception as e:
                st.error(f"❌ Error: {e}")
        else:
            st.warning("⚠️ Please fill all fields!")

elif menu == "🔓 Decrypt Image":
    st.header("Decrypt a Message from an Image")

    img_file = st.file_uploader("Upload an Encoded Image", type=["png"])
    password = st.text_input("🔑 Enter Password", type="password")

    if st.button("🔓 Decrypt Message"):
        if img_file and password:
            try:
                temp_image_path = "uploaded_encoded_image.png"
                image = Image.open(img_file)
                image.save(temp_image_path)

                hidden_data = lsb.reveal(temp_image_path)
                stored_hash = hidden_data[:60]  # Extract hashed password
                encrypted_msg = hidden_data[60:]  # Extract encrypted message

                if verify_password(stored_hash, password):
                    decrypted_msg = decrypt_message(encrypted_msg)
                    st.success("✅ Message Decrypted Successfully!")
                    st.text_area("📩 Decrypted Message", decrypted_msg, height=150)
                else:
                    st.error("❌ Incorrect password!")
            except Exception as e:
                st.error(f"❌ Error: {e}")
        else:
            st.warning("⚠️ Please upload an image and enter a password!")
