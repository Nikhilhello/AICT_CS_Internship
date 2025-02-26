import os
import streamlit as st
from PIL import Image
from stegano import lsb
from cryptography.fernet import Fernet
import bcrypt

# Generate a key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Function to hash password
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Function to verify password
def verify_password(stored_hash, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_hash.encode())

# Encrypt a message
def encrypt_message(message):
    return cipher_suite.encrypt(message.encode()).decode()

# Decrypt a message
def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message.encode()).decode()

# Streamlit UI
st.set_page_config(page_title="Steganography Tool", layout="centered")
st.title("🔏 Steganography Tool")

menu = st.radio("Select an Option", ["🔏 Encrypt Image", "🔓 Decrypt Image"])

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

                # Combine hashed password & encrypted message with a delimiter
                secret_data = hashed_password + "||" + encrypted_msg
                
                # Save uploaded image temporarily
                temp_image_path = "temp_image.png"
                image = Image.open(img_file)
                image.save(temp_image_path)

                # Encode message
                encoded_img = lsb.hide(temp_image_path, secret_data)
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
                # Save uploaded image temporarily
                temp_image_path = "uploaded_encoded_image.png"
                image = Image.open(img_file)
                image.save(temp_image_path)

                # Extract hidden data
                hidden_data = lsb.reveal(temp_image_path)

                # Extract hashed password and encrypted message
                parts = hidden_data.split("||", 1)  # Use a delimiter to split stored hash & encrypted message
                if len(parts) != 2:
                    st.error("❌ Data format is incorrect. Are you sure this is an encoded image?")
                else:
                    stored_hash, encrypted_msg = parts

                    # Verify password
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

# Footer
st.markdown("---")
st.markdown("📌 **Developed by Nikhil K.**")

