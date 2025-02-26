import os
import streamlit as st
from PIL import Image
from stegano import lsb
from cryptography.fernet import Fernet
import bcrypt

# Generate encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Function to hash passwords
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
st.title("🔐 Image Steganography Tool")

# Tab selection
tab1, tab2 = st.tabs(["Encrypt Image", "Decrypt Image"])

# **Encryption Tab**
with tab1:
    st.subheader("🛡️ Encrypt an Image")
    
    uploaded_image = st.file_uploader("Upload an image (PNG/JPG)", type=["png", "jpg"])
    secret_message = st.text_area("Enter the message to hide")
    password = st.text_input("Enter a secret password", type="password")

    if st.button("🔏 Encrypt and Save Image"):
        if uploaded_image and secret_message and password:
            try:
                # Save uploaded image temporarily
                img = Image.open(uploaded_image)
                img_path = "temp_image.png"
                img.save(img_path)

                # Encrypt message and hash password
                hashed_password = hash_password(password)
                encrypted_msg = encrypt_message(secret_message)

                # Concatenate password and message
                final_payload = f"{hashed_password}|||{encrypted_msg}"

                # Hide data in image
                encoded_img = lsb.hide(img_path, final_payload)
                encoded_img.save("encoded_image.png")

                st.success("✅ Image encrypted successfully!")
                st.download_button(label="📥 Download Encrypted Image", data=open("encoded_image.png", "rb").read(),
                                   file_name="encoded_image.png", mime="image/png")
            except Exception as e:
                st.error(f"❌ Encryption failed: {e}")
        else:
            st.warning("⚠️ Please provide all inputs.")

# **Decryption Tab**
with tab2:
    st.subheader("🔓 Decrypt an Image")

    uploaded_encoded_image = st.file_uploader("Upload an encrypted image", type=["png"])
    entered_password = st.text_input("Enter the password", type="password")

    if st.button("🔓 Decrypt Message"):
        if uploaded_encoded_image and entered_password:
            try:
                # Save uploaded encrypted image temporarily
                encoded_img_path = "uploaded_encoded_image.png"
                with open(encoded_img_path, "wb") as f:
                    f.write(uploaded_encoded_image.read())

                # Extract hidden data
                hidden_data = lsb.reveal(encoded_img_path)
                if hidden_data is None:
                    st.error("❌ Failed to decode the image. Ensure it's correctly encoded.")
                else:
                    # Extract password hash and encrypted message
                    try:
                        stored_hash, encrypted_msg = hidden_data.split("|||", 1)
                    except ValueError:
                        st.error("❌ Image does not contain a valid encoded message.")
                        st.stop()

                    # Debugging log
                    print(f"[DEBUG] Extracted Hash: {stored_hash}")
                    print(f"[DEBUG] Extracted Encrypted Message: {encrypted_msg}")

                    # Verify password
                    if verify_password(stored_hash, entered_password):
                        try:
                            decrypted_text = decrypt_message(encrypted_msg)
                            st.success("✅ Message decrypted successfully!")
                            st.text_area("Decrypted Message", decrypted_text, height=100)
                        except Exception as decryption_error:
                            st.error(f"❌ Error decrypting message: {decryption_error}")
                    else:
                        st.error("❌ Incorrect password!")

            except Exception as e:
                st.error(f"❌ Decryption failed: {e}")
        else:
            st.warning("⚠️ Please provide all inputs.")

# Footer
st.markdown("---")
st.markdown("👨‍💻 Developed by **Nikhil K.**")

