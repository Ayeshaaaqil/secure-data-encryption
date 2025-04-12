import streamlit as st
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
import secrets

# Set page configuration
st.set_page_config(
    page_title="Secure Data Encryption",
    page_icon="🔒",
    layout="wide"
)

# App title and description
st.title("🔒 Secure Data Encryption System")
st.markdown("""
This application allows you to securely encrypt and decrypt your sensitive data using 
industry-standard encryption algorithms. Choose between AES-256 and Fernet encryption.
""")

# Sidebar for encryption options
st.sidebar.header("Encryption Settings")
encryption_method = st.sidebar.selectbox(
    "Select Encryption Method",
    ["AES-256", "Fernet (AES-128)"]
)

# Function to derive an AES key from a password
def derive_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits for AES-256
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return key, salt

# Function to encrypt data using AES
def encrypt_aes(data, password):
    key, salt = derive_key(password)
    iv = os.urandom(16)  # Initialization vector
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Pad the data to be a multiple of 16 bytes (AES block size)
    padded_data = data.encode()
    padding_length = 16 - (len(padded_data) % 16)
    padded_data += bytes([padding_length]) * padding_length
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Combine salt, iv, and ciphertext for storage
    result = salt + iv + ciphertext
    return base64.b64encode(result).decode()

# Function to decrypt data using AES
def decrypt_aes(encrypted_data, password):
    try:
        # Decode the base64 data
        raw_data = base64.b64decode(encrypted_data)
        
        # Extract salt, iv, and ciphertext
        salt = raw_data[:16]
        iv = raw_data[16:32]
        ciphertext = raw_data[32:]
        
        # Derive the key using the same salt
        key, _ = derive_key(password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]
        
        return plaintext.decode()
    except Exception as e:
        st.error(f"Decryption failed: {str(e)}")
        return None

# Function to generate a Fernet key from a password
def generate_fernet_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

# Function to encrypt data using Fernet
def encrypt_fernet(data, password):
    key, salt = generate_fernet_key(password)
    f = Fernet(key)
    token = f.encrypt(data.encode())
    # Combine salt and token for storage
    result = salt + token
    return base64.b64encode(result).decode()

# Function to decrypt data using Fernet
def decrypt_fernet(encrypted_data, password):
    try:
        # Decode the base64 data
        raw_data = base64.b64decode(encrypted_data)
        
        # Extract salt and token
        salt = raw_data[:16]
        token = raw_data[16:]
        
        # Generate the key using the same salt
        key, _ = generate_fernet_key(password, salt)
        
        f = Fernet(key)
        plaintext = f.decrypt(token)
        
        return plaintext.decode()
    except Exception as e:
        st.error(f"Decryption failed: {str(e)}")
        return None

# Main app layout
tab1, tab2 = st.tabs(["Encrypt", "Decrypt"])

with tab1:
    st.header("Encrypt Your Data")
    
    # Input for data to encrypt
    data_to_encrypt = st.text_area("Enter text to encrypt:", height=150)
    
    # Password input
    password = st.text_input("Enter encryption password:", type="password")
    
    # Generate random password option
    if st.button("Generate Strong Password"):
        random_password = secrets.token_urlsafe(16)
        st.code(random_password)
        st.warning("Save this password securely! You'll need it to decrypt your data.")
    
    # Encrypt button
    if st.button("Encrypt Data"):
        if not data_to_encrypt:
            st.error("Please enter data to encrypt.")
        elif not password:
            st.error("Please enter a password.")
        else:
            with st.spinner("Encrypting..."):
                if encryption_method == "AES-256":
                    encrypted_result = encrypt_aes(data_to_encrypt, password)
                else:  # Fernet
                    encrypted_result = encrypt_fernet(data_to_encrypt, password)
                
                st.success("Data encrypted successfully!")
                st.text_area("Encrypted Data:", value=encrypted_result, height=150)
                st.download_button(
                    label="Download Encrypted Data",
                    data=encrypted_result,
                    file_name="encrypted_data.txt",
                    mime="text/plain"
                )

with tab2:
    st.header("Decrypt Your Data")
    
    # Input for data to decrypt
    data_to_decrypt = st.text_area("Enter encrypted text:", height=150)
    
    # Password input
    decrypt_password = st.text_input("Enter decryption password:", type="password")
    
    # Decrypt button
    if st.button("Decrypt Data"):
        if not data_to_decrypt:
            st.error("Please enter data to decrypt.")
        elif not decrypt_password:
            st.error("Please enter a password.")
        else:
            with st.spinner("Decrypting..."):
                if encryption_method == "AES-256":
                    decrypted_result = decrypt_aes(data_to_decrypt, decrypt_password)
                else:  # Fernet
                    decrypted_result = decrypt_fernet(data_to_decrypt, decrypt_password)
                
                if decrypted_result:
                    st.success("Data decrypted successfully!")
                    st.text_area("Decrypted Data:", value=decrypted_result, height=150)
                else:
                    st.error("Decryption failed. Please check your password and encrypted data.")

# Security information
st.markdown("---")
st.subheader("Security Information")
st.markdown("""
- **AES-256**: Advanced Encryption Standard with 256-bit key length, providing military-grade security.
- **Fernet**: Implementation of AES-128 in CBC mode with PKCS7 padding and HMAC using SHA256 for authentication.
- **Password Handling**: Your password is never stored and is only used to derive encryption keys.
- **Key Derivation**: PBKDF2 with 100,000 iterations is used to derive secure keys from your password.
""")

# Usage instructions
with st.expander("How to Use This App"):
    st.markdown("""
    1. **To Encrypt Data**:
       - Enter the text you want to encrypt
       - Create a strong password (or use the generated one)
       - Click "Encrypt Data"
       - Save the encrypted text and your password securely
    
    2. **To Decrypt Data**:
       - Enter the encrypted text
       - Enter the password used for encryption
       - Click "Decrypt Data"
       - View your original data
    
    3. **Security Best Practices**:
       - Use strong, unique passwords
       - Never share your encryption password through insecure channels
       - For highly sensitive data, consider additional security measures
    """)