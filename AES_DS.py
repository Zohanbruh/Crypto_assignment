import os
import tkinter as tk
from tkinter import filedialog

# =====================================================
# CRYPTOGRAPHY IMPORTS
# =====================================================
# We use:
# - ECDH (Elliptic Curve Diffie-Hellman) for key exchange
# - HKDF for deriving a symmetric AES key from the ECDH secret
# - AES-GCM for authenticated encryption
# - ECDSA for digital signatures
#
# These are modern, secure primitives widely used in real systems.
# =====================================================

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =====================================================
# KEY GENERATION (SIMULATED LONG‑TERM KEYS)
# =====================================================
# In a real-world secure system:
# - These keys would be generated once
# - Stored securely (HSM, TPM, encrypted key vault)
# - Loaded when needed
#
# For demonstration, we generate fresh keys each run.
# =====================================================

# Sender ECDH key pair (used to derive AES key)
sender_ecdh_private = ec.generate_private_key(ec.SECP256R1())
sender_ecdh_public = sender_ecdh_private.public_key()

# Sender signing key pair (used to sign ciphertext)
sender_sign_private = ec.generate_private_key(ec.SECP256R1())
sender_sign_public = sender_sign_private.public_key()

# Receiver ECDH key pair (used to derive AES key)
receiver_ecdh_private = ec.generate_private_key(ec.SECP256R1())
receiver_ecdh_public = receiver_ecdh_private.public_key()


# =====================================================
# FILE SELECTION (GUI OR ENVIRONMENT FALLBACK)
# =====================================================
# This function:
# - Opens a file picker window (Tkinter)
# - Allows the user to choose a file to encrypt
# - Supports a non-GUI fallback via AES_INPUT environment variable
# =====================================================

def select_file():
    """
    Opens a file dialog for selecting a file to encrypt.
    Falls back to AES_INPUT environment variable if set.
    """
    env_input = os.environ.get("AES_INPUT")
    if env_input and os.path.exists(env_input):
        return env_input

    # Create a hidden Tkinter root window
    root = tk.Tk()
    root.withdraw()

    # Open file picker
    return filedialog.askopenfilename(
        title="Select file to encrypt",
        filetypes=[("All Files", "*.*")]
    )


# =====================================================
# ECDH + HKDF KEY DERIVATION
# =====================================================
# ECDH gives us a shared secret between sender and receiver.
# HKDF expands that secret into a 256-bit AES key.
#
# This ensures:
# - No AES key is ever transmitted
# - Both sides derive the same key independently
# =====================================================

def derive_aes_key(private_key, peer_public_key):
    """
    Performs ECDH key exchange and derives a 256-bit AES key using HKDF-SHA256.
    """
    # Perform ECDH to get a shared secret
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    # HKDF expands the shared secret into a strong AES key
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256-bit AES key
        salt=None,
        info=b"secure-file-encryption",  # Context string
    ).derive(shared_secret)


# =====================================================
# AES-GCM ENCRYPTION
# =====================================================
# AES-GCM provides:
# - Confidentiality (encryption)
# - Integrity (GCM tag)
# - Authentication (detects tampering)
#
# The nonce must be unique per encryption.
# =====================================================

def encrypt_file(filepath, aes_key):
    """
    Encrypts a file using AES-256-GCM.
    Returns (nonce, ciphertext).
    """
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    aesgcm = AESGCM(aes_key)

    with open(filepath, "rb") as f:
        plaintext = f.read()

    # AES-GCM returns ciphertext + authentication tag
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


# =====================================================
# AES-GCM DECRYPTION
# =====================================================
# AES-GCM automatically verifies the authentication tag.
# If tampering occurred, decryption fails.
# =====================================================

def decrypt_file(nonce, ciphertext, aes_key):
    """
    Decrypts AES-GCM ciphertext and verifies integrity.
    """
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# =====================================================
# DIGITAL SIGNATURES (ECDSA)
# =====================================================
# We sign (nonce + ciphertext) to ensure:
# - Authenticity (sender is genuine)
# - Integrity (ciphertext not modified)
#
# Receiver verifies signature before decrypting.
# =====================================================

def sign_data(private_key, data):
    """
    Signs data using ECDSA-SHA256.
    """
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_signature(public_key, signature, data):
    """
    Verifies ECDSA signature.
    Raises exception if invalid.
    """
    public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))


# =====================================================
# MANUAL DECRYPTION MODE
# =====================================================
# This mode simulates a forensic or debugging scenario where:
# - The user manually enters nonce + ciphertext
# - AES key is still derived securely via ECDH
#
# This demonstrates that the ciphertext is portable and decryptable.
# =====================================================

def manual_decryption(receiver_private_key, sender_public_key):
    """
    Allows the user to manually enter nonce and ciphertext (hex)
    while deriving the AES key securely via ECDH.
    """
    print("\n=== MANUAL DECRYPTION MODE ===")

    # User enters hex-encoded values printed earlier
    nonce_hex = input("Enter Nonce (hex): ")
    ciphertext_hex = input("Enter Ciphertext (hex): ")

    # Convert hex → bytes
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    # Derive AES key using ECDH
    aes_key = derive_aes_key(receiver_private_key, sender_public_key)

    try:
        plaintext = decrypt_file(nonce, ciphertext, aes_key)
        print("\n✔ Decryption Successful")
        print("Decrypted Data:\n")
        print(plaintext.decode(errors="ignore"))
    except Exception as e:
        print("\n❌ Decryption Failed:", e)


# =====================================================
# MAIN PROGRAM FLOW
# =====================================================

def main():
    print("\n=== SECURE FILE ENCRYPTION SYSTEM (MANUAL DECRYPTION ONLY) ===\n")

    # -------------------------
    # FILE SELECTION
    # -------------------------
    file_path = select_file()
    if not file_path or not os.path.exists(file_path):
        print("❌ No file selected")
        return

    print("✔ File selected:", file_path)

    # -------------------------
    # SENDER SIDE — ENCRYPTION
    # -------------------------

    # Derive AES key using ECDH (sender side)
    aes_key_sender = derive_aes_key(sender_ecdh_private, receiver_ecdh_public)

    # Encrypt the file
    nonce, ciphertext = encrypt_file(file_path, aes_key_sender)

    # Prepare data for signing (nonce + ciphertext)
    data_to_sign = nonce + ciphertext

    # Sign the encrypted data
    signature = sign_data(sender_sign_private, data_to_sign)

    # Export sender's signing public key (PEM format)
    sender_sign_pub_bytes = sender_sign_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("\n✔ File encrypted and signed")

    # -------------------------
    # SAVE ENCRYPTED FILE
    # -------------------------
    # We store nonce + ciphertext together.
    # The receiver must know the nonce to decrypt.
    with open("encrypted_output.bin", "wb") as f:
        f.write(nonce + ciphertext)

    print("✔ Encrypted file saved as 'encrypted_output.bin'")

    # -------------------------
    # PRINT VALUES FOR MANUAL DECRYPTION
    # -------------------------
    print("\n--- VALUES FOR MANUAL DECRYPTION ---")
    print("Nonce (hex):", nonce.hex())
    print("Ciphertext (hex):", ciphertext.hex())

    # -------------------------
    # RECEIVER SIDE — SIGNATURE VERIFICATION
    # -------------------------
    # Receiver loads sender's signing public key
    trusted_sender_pub = serialization.load_pem_public_key(sender_sign_pub_bytes)

    try:
        verify_signature(trusted_sender_pub, signature, data_to_sign)
        print("✔ Signature verified (Sender authenticated)")
    except Exception:
        print("❌ Signature verification failed")
        return

    # -------------------------
    # MANUAL DECRYPTION ONLY
    # -------------------------
    manual_decryption(receiver_ecdh_private, sender_ecdh_public)


if __name__ == "__main__":
    main()
