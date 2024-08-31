import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
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
# AES_KEY_PATH = os.path.join(KEY_PATH, "aes_key")
ENC_KEY_PATH = os.path.join(KEY_PATH, "encrypted_aes_key")
PUB_KEY_PATH = os.path.join(KEY_PATH, "pub_key")
MASTER_KEY_PATH = os.path.join(KEY_PATH, "master_key")

CPABE_PATH = './cpabe-0.11'



# Step 1: AES Encryption of the file
def encrypt_file_aes(name, key):
    # Generate a random IV for GCM mode
    file_path = os.path.join(PLAIN_FILE_PATH,name)
    enc_file = os.path.join(ENC_FILE_PATH,'enc_'+name)

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
    with open(enc_file, 'wb') as f:
        f.write(iv + encryptor.tag + ciphertext)
    
    return ciphertext, encryptor.tag, iv

def decrypt_file_aes(name, key):
    # Read the encrypted data
    enc_file_path = os.path.join(ENC_FILE_PATH, "enc_"+name)
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

    dec_file = "dec_"+name
    dec_file_path = os.path.join(DEC_FILE_PATH,dec_file)
    with open(dec_file_path, 'wb') as f:
        f.write(plaintext)
    
    return plaintext

# Step 2: Padding the AES key at the start and end
def pad_aes_key(key):
    start_padding = os.urandom(start_pad_size)  # Generate random 128-bit (16 bytes) padding for the start
    end_padding = os.urandom(end_pad_size)      # Generate random 128-bit (16 bytes) padding for the end
    
    # Combine start padding, key, and end padding
    padded_key = start_padding + key + end_padding
    return padded_key

# Step 3: Encrypt the padded AES key with CP-ABE
def encrypt_key_cpabe(padded_key, policy, name):
    # Write the padded key to a temporary file
    with open('temp_padded_key.bin', 'wb') as f:
        f.write(padded_key)
    
    # Use the CP-ABE Docker image to encrypt the key
    cpabe_enc = os.path.join(CPABE_PATH,'cpabe-enc')
    file_name = "enc_padded_aes_key_" + name
    output_path = os.path.join(KEY_PATH,file_name)

    subprocess.run([cpabe_enc, '-k', PUB_KEY_PATH, 'temp_padded_key.bin', policy, '-o', output_path], check=True)
    
    # Clean up the temporary file
    os.remove('temp_padded_key.bin')

# Function to Generate file with specific size
def generate_file(filename, size_mb):
    # Size in bytes
    size_bytes = size_mb * 1024 * 1024
    file_path = os.path.join(PLAIN_FILE_PATH,filename)
    # Generate random data
    with open(file_path, 'wb') as f:
        f.write(os.urandom(size_bytes))

def generate_aes_key(name):
    key_name = "aes_key_" + name
    AES_KEY_PATH = os.path.join(KEY_PATH,key_name)
    aes_key = os.urandom(AES_KEY_SIZE)

    with open(AES_KEY_PATH, 'wb') as f:
        f.write(aes_key)
    
def use_aes_key(name):
    key_name = "aes_key_" + name
    AES_KEY_PATH = os.path.join(KEY_PATH,key_name)
    with open(AES_KEY_PATH, 'rb') as f:
        aes_key = f.read()
    return aes_key


def encryption(file_size):
    name = str(file_size)+"MB"
    generate_file(name,file_size)

 # Generate a random AES key
    generate_aes_key(name)
    aes_key = use_aes_key(name)
        
 # Encrypt the file with AES
    start_time = timeit.default_timer()
    start_enc_file_time = timeit.default_timer()
    encrypt_file_aes(name, aes_key)
    stop_enc_file_time = timeit.default_timer()

 # Pad the AES key
    start_enc_aes_key_time = timeit.default_timer()
    padded_key = pad_aes_key(aes_key)

 # Policy for encrypt with CPABE
    policy = "((A and B) or (C and D)) and E"

 # Encrypt the padded AES key with CP-ABE
    encrypt_key_cpabe(padded_key,policy, name)
    stop_enc_aes_key_time = timeit.default_timer()
    stop_time = timeit.default_timer()

    enc_file_time = stop_enc_file_time - start_enc_file_time
    enc_aes_key_time = stop_enc_aes_key_time - start_enc_aes_key_time
    total_time = stop_time-start_time

 # Decrypt file with AES key
    decrypt_file_aes(name,aes_key)
    
    print(f'''
          ========================================================
          Time that use for ENCRYPT --- {file_size} MB file --- is 
          
          TOTAL TIME        =>  {total_time} secs
          ENC FILE TIME     =>  {enc_file_time} secs
          ENC AES KEY TIME  =>  {enc_aes_key_time} secs
          ========================================================
          ''')


# Main Function
def main():
    file_size = [1,10,100]
    for i in file_size:
        for j in range(3):
            encryption(i)

if __name__ == '__main__':
    main()
