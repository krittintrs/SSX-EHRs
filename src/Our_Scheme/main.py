import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import subprocess 
import timeit
import filecmp

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


## ENCRYPT

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

def encryption(file_size, file_format):
    if file_format == "bytes":
        name = str(file_size)+"bytes"
        generate_file_byte(name, file_size)
    elif file_format == "MB":
        name = str(file_size)+"MB"
        generate_file_MB(name, file_size)

 # Generate a random AES key
    generate_aes_key(name)
    aes_key = use_aes_key(name)
        
 # STEP 1: Encrypt the file with AES
    start_time = timeit.default_timer()
    start_enc_file_time = timeit.default_timer()
    encrypt_file_aes(name, aes_key)
    stop_enc_file_time = timeit.default_timer()

 # STEP 2: Pad the AES key
    start_enc_aes_key_time = timeit.default_timer()
    padded_key = pad_aes_key(aes_key)

 # Policy for encrypt with CPABE
    policy = "((A and B) or (C and D)) and E"

 # STEP 3: Encrypt the padded AES key with CP-ABE
    encrypt_key_cpabe(padded_key,policy, name)
    stop_enc_aes_key_time = timeit.default_timer()
    stop_time = timeit.default_timer()

    enc_file_time = stop_enc_file_time - start_enc_file_time
    enc_aes_key_time = stop_enc_aes_key_time - start_enc_aes_key_time
    total_time = stop_time-start_time
    
    print(f'''
          ========================================================
          Time that use for ENCRYPT --- {name} file --- is 
          
          TOTAL ENC TIME    =>  {total_time} secs
          ENC FILE TIME     =>  {enc_file_time} secs
          ENC AES KEY TIME  =>  {enc_aes_key_time} secs
          --------------------------------------------------------''')
#=========================END ENCYPRT===========================#


## DECRYPT
# Step 1: Decrypt padded AES KEY with cpabe key
def decrypt_key_cpabe(name, priv_key):
    cpabe_dec = os.path.join(CPABE_PATH,'cpabe-dec')
    PRIV_KEY_PATH = os.path.join(KEY_PATH,priv_key) 
    enc_padded_aes_key = "enc_padded_aes_key_" + name
    padded_aes_key_path = os.path.join(KEY_PATH,enc_padded_aes_key)
    output_name = "dec_padded_aes_key_"+name
    output_path = os.path.join(KEY_PATH, output_name)

    subprocess.run([cpabe_dec, "-k", PUB_KEY_PATH, PRIV_KEY_PATH, padded_aes_key_path, "-o", output_path])

# Step 2: Unpad decrypted padded AES KEY
def unpad_aes_key(name):
    padded_aes_key = "dec_padded_aes_key_" + name
    padded_aes_key_path = os.path.join(KEY_PATH,padded_aes_key)

    with open(padded_aes_key_path, 'rb') as f:
        padded_aes_key = f.read()
    
    unpadded_aes_key = padded_aes_key[start_pad_size:-end_pad_size]

    return unpadded_aes_key

# Step 3: Decrypt encrypted file with unpadded AES KEY
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

## DECRYPT

def decryption(file_size, file_format):
    
    name = str(file_size) + file_format

    start_time = timeit.default_timer()
    # Step 1: decrypt padded AES KEY with cpabe key
    priv_key = "test_priv"
    decrypt_key_cpabe(name,priv_key)

    # Step 2: Unpad AES KEY and decrypt file with unpadded AES KEY
    unpadded_aes_key = unpad_aes_key(name)
    decrypt_file_aes(name,unpadded_aes_key)

    stop_time = timeit.default_timer()

    total_time = stop_time - start_time

    input_file = os.path.join(PLAIN_FILE_PATH, name)
    output_file = os.path.join(DEC_FILE_PATH, "dec_{}".format(name))

    # Compare the original file with the decrypted file
    if compare_files(input_file, output_file):
        print(f'          File decryption ✅✅successful✅✅ file size: {name}')
    else:
        print(f'          File decryption ❌❌failed❌❌ file size: {name}')

    print(f'''          
          Time that use for DECRYPT --- {name} file --- is 
        
          TOTAL DEC TIME    =>  {total_time} secs
          ========================================================
          ''')
#=========================END DECYPRT===========================#

## Utilize FUNC
# Function to Generate file with specific size
def generate_file_MB(filename, size_mb):
    # Size in bytes
    size_bytes = size_mb * 1024 * 1024
    file_path = os.path.join(PLAIN_FILE_PATH,filename)
    # Generate random data
    with open(file_path, 'wb') as f:
        f.write(os.urandom(size_bytes))

def generate_file_byte(filename, size_bytes):
    # Size in bytes
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

def compare_files(file1, file2):
    return filecmp.cmp(file1, file2, shallow=False)

#=========================END Utilize===========================#
# Main Function
def main():
    file_sizes = [50000,100000,200000,400000,800000,1600000]
    file_format = "bytes" # bytes or MB
    for j in range(2):    
        for i in file_sizes:
            encryption(i, file_format)
            decryption(i, file_format)
        print("#############################################################################")

if __name__ == '__main__':
    main()
