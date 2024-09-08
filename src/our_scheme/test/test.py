import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import subprocess
import timeit

# Constants
AES_KEY_SIZE = 32  # 256 bits
start_pad_size=16 # 128 bits
end_pad_size=16 # 128 bits
IV_SIZE = 12  # 96 bits for GCM mode
FILE_PATH = './file'
PLAIN_FILE_PATH = os.path.join(FILE_PATH,'plain_file')
ENC_FILE_PATH = os.path.join(FILE_PATH,'encrypted_file')
DEC_FILE_PATH = os.path.join(FILE_PATH,'decrypted_file')

KEY_PATH = "./key"
AES_KEY_PATH = os.path.join(KEY_PATH, "aes_key")
ENC_KEY_PATH = os.path.join(KEY_PATH, "encrypted_aes_key")
PUB_KEY_PATH = os.path.join(KEY_PATH, "pub_key")
MASTER_KEY_PATH = os.path.join(KEY_PATH, "master_key")

CPABE_PATH = './cpabe-0.11'


# Step 1: AES Encryption of the file
def encrypt_file_aes(file_path, key):
    # Generate a random IV for GCM mode
    iv = os.urandom(IV_SIZE)
    
    # Create AES-GCM Cipher object
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    # Read the file data
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    # Encrypt the data
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Write the encrypted data to a file
    with open(ENC_FILE_PATH, 'wb') as f:
        f.write(iv + encryptor.tag + ciphertext)
    
    return ciphertext, encryptor.tag, iv

def decrypt_file_aes(enc_file_path, key):
    # Read the encrypted data
    with open(enc_file_path, 'rb') as f:
        iv = f.read(IV_SIZE)  # Extract the IV (first 12 bytes)
        tag = f.read(16)       # Extract the tag (next 16 bytes)
        ciphertext = f.read()  # The rest is the ciphertext
    
    # Create AES-GCM Cipher object for decryption
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    
    # Decrypt the data
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open('./decrypted_file', 'wb') as f:
        f.write(plaintext)
    
    return plaintext

def encrypt_key_cpabe(padded_key, policy):
    # Write the padded key to a temporary file
    cpabe_enc = os.path.join(CPABE_PATH,'cpabe-enc')
    output_path = "./cp-enc_500MB"
    subprocess.run([cpabe_enc, '-k', PUB_KEY_PATH, padded_key, policy, '-o', output_path], check=True)



start_enc_aes_key_time = timeit.default_timer()

# Policy for encrypt with CPABE
policy = "((A and B) or (C and D)) and E"

# Encrypt the padded AES key with CP-ABE
encrypt_key_cpabe("./file/plain_file/1000MB",policy)
stop_enc_aes_key_time = timeit.default_timer()

enc_aes_key_time = stop_enc_aes_key_time - start_enc_aes_key_time

print(f'''
        ========================================================
        ENC by CP-ABE TIME  =>  {enc_aes_key_time} secs
        ========================================================
        ''')