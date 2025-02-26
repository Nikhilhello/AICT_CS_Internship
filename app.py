import os
import streamlit as st
from PIL import Image
from stegano import lsb
from cryptography.fernet import Fernet
import bcrypt

import streamlit as st

# Sidebar Theme Toggle
theme_option = st.sidebar.radio("🌓 Select Theme", ["🌞 Light", "🌙 Dark"], index=1)

# Define Theme Colors
light_theme = {
    "backgroundColor": "#ffffff",
    "secondaryBackgroundColor": "#f0f2f6",
    "textColor": "#000000",
    "primaryColor": "#ff4b4b",
    "buttonColor": "#ff4b4b",
    "buttonText": "#ffffff",
}

dark_theme = {
    "backgroundColor": "#0e1117",
    "secondaryBackgroundColor": "#262730",
    "textColor": "#ffffff",
    "primaryColor": "#ff4b4b",
    "buttonColor": "#1e90ff",
    "buttonText": "#ffffff",
}

# Apply Selected Theme
theme = dark_theme if theme_option == "🌙 Dark" else light_theme

# Apply Custom CSS for Smooth Theme Transition & UI Enhancements
st.markdown(
    f"""
    <style>
        /* Background and Text */
        .stApp {{
            background-color: {theme["backgroundColor"]} !important;
            color: {theme["textColor"]} !important;
            transition: background-color 0.5s ease-in-out, color 0.5s ease-in-out;
        }}
        
        /* Sidebar */
        .stSidebar {{
            background-color: {theme["secondaryBackgroundColor"]} !important;
        }}

        /* Buttons */
        .stButton > button {{
            background-color: {theme["buttonColor"]} !important;
            color: {theme["buttonText"]} !important;
            border-radius: 8px;
            transition: background-color 0.3s ease-in-out;
        }}

        /* Button Hover */
        .stButton > button:hover {{
            background-color: #ff5733 !important;
            color: #ffffff !important;
        }}

        /* Inputs and Text Areas */
        .stTextInput > div > div > input, .stTextArea > div > textarea {{
            background-color: {theme["secondaryBackgroundColor"]} !important;
            color: {theme["textColor"]} !important;
            border-radius: 5px;
        }}

        /* Titles and Headers */
        h1, h2, h3, h4, h5, h6 {{
            color: {theme["textColor"]} !important;
        }}

        /* Ensuring All Text is Visible */
        p, span, div, label, li, ul, ol, table, td, th {{
            color: {theme["textColor"]} !important;
        }}

        /* Fixing Specific Labels & Text Fields */
        .stTextInput label, .stTextArea label, .stRadio label {{
            color: {theme["textColor"]} !important;
        }}

        /* Fixing Selectbox and Checkbox Text */
        .stSelectbox div, .stCheckbox div {{
            color: {theme["textColor"]} !important;
        }}
    </style>
    """,
    unsafe_allow_html=True
)
st.markdown(
    f"""
    <style>
        /* File Uploader Styling */
        div[data-testid="stFileDropzone"] div div {{
            color: {theme["textColor"]} !important;  /* Ensure text is visible */
            font-weight: bold;
        }}

        div[data-testid="stFileDropzone"] {{
            border: 2px dashed {theme["textColor"]} !important; /* Visible border */
            background-color: {theme["secondaryBackgroundColor"]} !important;
            border-radius: 10px;
            padding: 20px;
        }}
    </style>
    """,
    unsafe_allow_html=True
)








# Store the encryption key persistently
KEY_FILE = "secret.key"

def get_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

# Load or create the encryption key
key = get_or_create_key()
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

tab1, tab2, tab3 = st.tabs(["Encrypt Image", "Decrypt Image","❓ Help"])

# **Encryption Tab**
with tab1:
    st.subheader("🛡️ Encrypt an Image")
    
    uploaded_image = st.file_uploader("Upload an image (PNG/JPG)", type=["png", "jpg"])
    secret_message = st.text_area("Enter the message to hide")
    password = st.text_input("Enter a secret password", type="password")

    if st.button("🔏 Encrypt and Save Image"):
        if uploaded_image and secret_message and password:
            try:
                img = Image.open(uploaded_image)
                img_path = "temp_image.png"
                img.save(img_path)

                # Encrypt message & hash password
                hashed_password = hash_password(password)
                encrypted_msg = encrypt_message(secret_message)

                # Concatenate hash and encrypted message
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
                encoded_img_path = "uploaded_encoded_image.png"
                with open(encoded_img_path, "wb") as f:
                    f.write(uploaded_encoded_image.read())

                # Extract hidden data
                hidden_data = lsb.reveal(encoded_img_path)
                if hidden_data is None:
                    st.error("❌ Failed to decode the image. Ensure it's correctly encoded.")
                    st.stop()

                # Extract password hash and encrypted message
                try:
                    stored_hash, encrypted_msg = hidden_data.split("|||", 1)
                except ValueError:
                    st.error("❌ Image does not contain a valid encoded message.")
                    st.stop()

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

with tab3:
    st.markdown("""
    ## 🛠 How to Use the Steganography Tool?
    
    1️⃣ **Encryption:**
    - Upload an image.
    - Enter a secret message and a password.
    - Click "Encrypt" to hide the message in the image.
    - Download the encoded image.

    2️⃣ **Decryption:**
    - Upload the encoded image.
    - Enter the correct password.
    - Click "Decrypt" to reveal the hidden message.

    ⚠ **Important Notes:**
    - Use the same password to decrypt the message.
    - Only images encoded using this tool can be decrypted.
    - If decryption fails, ensure the correct password and image are used.
    """)


with st.sidebar:
    if st.button("📌 Notes / Info"):
        st.markdown("""
        ## 📝 Important Notes & Process Explanation  

        🔹 **Input Image Formats:** You can upload images in **PNG, JPG, or JPEG** formats.  
        🔹 **Output Format:** The encoded image will always be saved in **PNG format**.  

        ### 🔄 Why is the output in PNG format?  
        - **PNG is a lossless format**, meaning it does not compress image data, which is important for hiding messages without data loss.  
        - **JPG/JPEG are lossy formats**, which means they compress and change pixel values, potentially corrupting hidden messages.  
        - To **preserve message integrity**, all encoded images are converted to **PNG** automatically.  

        ### 🔧 Encoding Process:  
        1️⃣ Upload an image (PNG, JPG, JPEG).  
        2️⃣ Enter a secret message and a password.  
        3️⃣ The message is encrypted and hidden inside the image.  
        4️⃣ The encoded image is saved as **PNG** to avoid data loss.  
        5️⃣ During decryption, the tool extracts and decrypts the hidden message.  

        ⚠ **Note:** Always use the same password for decryption, and ensure the encoded image is in **PNG format** when decoding.  
        """)

st.markdown("---")
st.markdown(
    "<div style='text-align: center;'>👨‍💻 Developed by Nikhil K.</div>",
    unsafe_allow_html=True
)


