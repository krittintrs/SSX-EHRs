import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import subprocess 
import time
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
def encrypt_file_aes(plaintext, key):
    # Generate a random IV for GCM mode
    # file_path = os.path.join(PLAIN_FILE_PATH,name)
    # enc_file = os.path.join(ENC_FILE_PATH,'enc_'+name)

    iv = os.urandom(IV_SIZE)
    
    # Create AES-GCM Cipher object
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    # # Read the file data
    # with open(file_path, 'rb') as f:
    #     plaintext = f.read()
    
    # Encrypt the data
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # # Write the encrypted data to a file
    # with open(enc_file, 'wb') as f:
    #     f.write(iv + encryptor.tag + ciphertext)
    
    return ciphertext, encryptor.tag, iv

# Step 2: Padding the AES key at the start and end
def pad_aes_key(key):
    start_padding = os.urandom(start_pad_size)  # Generate random 128-bit (16 bytes) padding for the start
    end_padding = os.urandom(end_pad_size)      # Generate random 128-bit (16 bytes) padding for the end
    
    # Combine start padding, key, and end padding
    padded_key = start_padding + key + end_padding
    return padded_key

# Step 3: Encrypt the padded AES key with CP-ABE
def encrypt_key_cpabe(padded_key, policy, name, pub_key):
    # Write the padded key to a temporary file
    with open('temp_padded_key.bin', 'wb') as f:
        f.write(padded_key)
    
    # Use the CP-ABE Docker image to encrypt the key
    cpabe_enc = os.path.join(CPABE_PATH,'cpabe-enc')
    file_name = "enc_padded_aes_key_" + name
    output_path = os.path.join(KEY_PATH,file_name)

    subprocess.run([cpabe_enc, '-k', pub_key, 'temp_padded_key.bin', policy, '-o', output_path], check=True)
    
    # Clean up the temporary file
    os.remove('temp_padded_key.bin')

def encryption(plaintext, aes_key, pub_key, policy, name): # name for output of cpabe enc

 # STEP 1: Encrypt the file with AES
    start_time = time.time()
    start_enc_file_time = time.time()
    ciphertext, encryptor, iv = encrypt_file_aes(plaintext, aes_key)
    stop_enc_file_time = time.time()

 # STEP 2: Pad the AES key
    start_enc_aes_key_time = time.time()
    padded_key = pad_aes_key(aes_key)

 # STEP 3: Encrypt the padded AES key with CP-ABE
    encrypt_key_cpabe(padded_key, policy, name, pub_key)
    stop_enc_aes_key_time = time.time()
    stop_time = time.time()

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
    return ciphertext, encryptor, iv, total_time, enc_file_time, enc_aes_key_time
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
def unpad_aes_key(padded_aes_key):
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

def decryption(name, padded_aes_key, input_file):

    start_time = time.time()
    # Step 1: decrypt padded AES KEY with cpabe key
    priv_key = "test_priv"
    decrypt_key_cpabe(name,priv_key)

    # Step 2: Unpad AES KEY and decrypt file with unpadded AES KEY
    unpadded_aes_key = unpad_aes_key(padded_aes_key)
    decrypt_file_aes(name,unpadded_aes_key)

    stop_time = time.time()

    total_time = stop_time - start_time

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
    return total_time
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
    file_sizes = [50_000, 100_000, 200_000, 400_000, 800_000, 1_600_000]
    n = len(file_sizes)
    input_file_dir = '../sample/input/'
    output_file_dir = '../sample/output/'
    output_txt = './our.txt'

    with open(output_txt, 'w+', encoding='utf-8') as f:
        f.write('{:7} {:18} {:18} {:18} {:18} {:18} {:18}\n'.format(
            'Size', 'EncAveTime', 'AesEncAveTime', 'CpabeAveTime', '??TIME', 'PREAveTime', 'DecAveTime'
        ))

        for i in range(n):
            enc_tot, aes_enc_tot, cp_enc_tot, unknown_tot , pre_tot, dec_tot = 0.0, 0.0, 0.0, 0.0, 0.0, 0.0

            for j in range(n):
                #---ENCRYPT---#
                file_size = file_sizes[i]
                print(f'\nFile size: {file_size} bytes, seq: {j}')

                name = str(file_size)+"bytes"

                # Policy for encrypt with CPABE
                policy = "((A and B) or (C and D)) and E"

                # Generate a random AES key
                generate_aes_key(name)
                aes_key = use_aes_key(name)

                pub_key = PUB_KEY_PATH

                # get plain text
                input_file = f'{input_file_dir}input_file_{file_size}.bin'
                with open(input_file, 'rb') as f_in:
                    plaintext = f_in.read()

                # encrypt
                ciphertext, encryptor, iv, enc_time, aes_enc_time, cp_enc_time = encryption(plaintext, aes_key, pub_key, policy, name)
                
                # output file
                enc_file = os.path.join(ENC_FILE_PATH,'enc_'+name)
                with open(enc_file, 'wb') as file:
                    file.write(iv + encryptor+ ciphertext)

                enc_tot += enc_time
                aes_enc_tot += aes_enc_time
                cp_enc_tot += cp_enc_time
                #---END ENCRYPT---#
                
                #---DECRYPT---#
                padded_aes_key_name = "dec_padded_aes_key_" + name
                dec_time = decryption(name, padded_aes_key_name, input_file)

                dec_tot += dec_time
                #---END DECRYPT---#
                print(f"Total time for this run: ",enc_tot+aes_enc_tot+cp_enc_tot+unknown_tot+pre_tot+dec_tot)

            # Write the average times for the current file size
            avg_enc_time = enc_tot / n
            avg_aes_enc_time = aes_enc_tot / n
            avg_cp_enc_time = cp_enc_tot / n
            avg_pre_time = pre_tot / n
            avg_unknown_time = unknown_tot / n
            avg_decryption_time = dec_tot / n

            out0 = str(file_sizes[i]).zfill(7)
            out1 = str(format(avg_enc_time, '.16f'))
            out2 = str(format(avg_aes_enc_time, '.16f'))
            out3 = str(format(avg_cp_enc_time, '.16f'))
            out4 = str(format(avg_unknown_time, '.16f'))
            out5 = str(format(avg_pre_time, '.16f'))
            out6 = str(format(avg_decryption_time, '.16f'))

            f.write(f'{out0} {out1} {out2} {out3} {out4} {out5} {out6}\n')

if __name__ == '__main__':
    main()
