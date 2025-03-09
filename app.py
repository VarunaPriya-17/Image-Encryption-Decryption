import streamlit as st
st.set_page_config(page_title="🔒 Image Encryption & Decryption", layout="centered")
try:
    from Cryptodome.Cipher import AES  # ✅ Preferred Import
except ImportError:
    from Crypto.Cipher import AES  # 🔄 Alternative Import
import base64
import os
import json
import hashlib
from PIL import Image
import io
st.markdown(
    """
    <style>
    body {
        background-color: #0d0d0d;
        color: #00ffcc;
    }
    .stApp {
        background-color: #0d0d0d;
    }
    /* Image encryption and decryption heading */
    h2 {
        text-align: center;
        color: #00ffcc;
        font-size: 40px;
        text-shadow: 0px 0px 10px #00ffcc;
    }
    /* "Choose an Option:" white */
    .stRadio label {
        color: white !important;
        font-size: 20px;
    }
    /* Radio Button Text (Encrypt/Decrypt) Light Grey */
    div[role="radiogroup"] label {
        color: white !important;  
    }
    /* File Uploader Text Light Grey */
    .stFileUploader label {
        color: white !important;  /* Light grey */
        font-size: 14px;
    }
    /* Uploaded Filename Light Grey */
    div[data-testid="stFileUploader"] div {
        color: white !important;
    }
    /* Drag & Drop Box - Black */
    div[data-testid="stFileDropzone"] {
        background-color: black !important;
        border: 2px dashed #00ffcc !important;
    }
    /* Change "Drag and drop file here" to Black */
    div[data-testid="stFileDropzone"] div {
        color: black !important;
    }
    /* Green Color for "Upload Image" Headings */
    h3 {
        color: #00ffcc !important;
        font-size: 26px;
    }
    .stButton>button {
        border: 2px solid #00ffcc;
        background: transparent;
        color: #00ffcc;
        font-size: 16px;
        padding: 10px;
        border-radius: 10px;
        transition: 0.3s;
    }
    .stButton>button:hover {
        background: #00ffcc;
        color: black;
        box-shadow: 0px 0px 10px #00ffcc;
    }
    .stTextInput > div > div > input {
        background-color: #222222;
        color: #00ffcc;
        border: 1px solid #00ffcc;
        border-radius: 5px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.markdown("<h2>🔒 Image Encryption & Decryption</h2>", unsafe_allow_html=True)
PASSWORD_FILE = "passwords.json"
def load_passwords():
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "r") as file:
            return json.load(file)
    return {}
def save_password(username, password):
    passwords = load_passwords()
    passwords[username] = password
    with open(PASSWORD_FILE, "w") as file:
        json.dump(passwords, file)
def generate_key(password):
    return hashlib.sha256(password.encode()).digest()
option = st.radio("Choose an Option:", ["🔐 Encrypt Image", "🔓 Decrypt Image"])
if option == "🔐 Encrypt Image":
    st.markdown("<h3>Upload an Image to Encrypt</h3>", unsafe_allow_html=True)
    uploaded_file = st.file_uploader("Choose an image...", type=["png", "jpg", "jpeg"])
    if uploaded_file:
        st.image(uploaded_file, caption="Uploaded Image", use_container_width=True)
        username = st.text_input("Enter your username:")
        password = st.text_input("Enter a password to encrypt:", type="password")
        if st.button("Encrypt Image"):
            if username and password:
                image = Image.open(uploaded_file)
                img_bytes = io.BytesIO()
                image.save(img_bytes, format='PNG')
                key = generate_key(password)
                cipher = AES.new(key, AES.MODE_EAX)
                ciphertext, tag = cipher.encrypt_and_digest(img_bytes.getvalue())
                encrypted_data = cipher.nonce + tag + ciphertext
                encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
                save_password(username, password)
                st.success("✨ Image Encrypted Successfully! ✨")
                st.download_button("📥 Download Encrypted Image", encoded_data, file_name="encrypted_image.enc")
            else:
                st.warning("⚠ Please enter both username and password.")
if option == "🔓 Decrypt Image":
    st.markdown("<h3>Upload an Encrypted Image to Decrypt</h3>", unsafe_allow_html=True)
    uploaded_file = st.file_uploader("Upload Encrypted File...", type=["enc"])
    if uploaded_file:
        username = st.text_input("Enter your username:")
        password = st.text_input("Enter decryption password:", type="password")
        if st.button("Decrypt Image"):
            passwords = load_passwords()
            if username in passwords and passwords[username] == password:
                try:
                    encoded_data = uploaded_file.read().decode('utf-8')
                    encrypted_data = base64.b64decode(encoded_data)
                    nonce = encrypted_data[:16]
                    tag = encrypted_data[16:32]
                    ciphertext = encrypted_data[32:]
                    key = generate_key(password)
                    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
                    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
                    image = Image.open(io.BytesIO(decrypted_data))
                    img_bytes = io.BytesIO()
                    image.save(img_bytes, format='PNG')
                    st.success("✨ Image Decrypted Successfully! ✨")
                    st.image(image, caption="Decrypted Image", use_container_width=True)
                    st.download_button("📥 Download Decrypted Image", img_bytes.getvalue(), file_name="decrypted_image.png")
                except Exception:
                    st.error("❌ Wrong Password! Decryption Failed.")
            else:
                st.error("❌ Incorrect Username or Password.")
