CPABE_PATH = './cpabe-0.11'
KEY_PATH = "./key"
import subprocess 
import os
PUB_KEY_PATH = "./pub_key"
PG_cpabe_sk = "proxy_sk"

def enc_key_cpabe(padded_key, dec_check, dub, n):
    # Perform CP-ABE decryption
    temp_path = os.path.join(KEY_PATH, f'temp_padded_key_{dub}_{n}.bin')
    print(f'temp_path: {temp_path}')
    with open(temp_path, 'rb') as f:
        real_padded_key = f.read()
        
    CT_padded_key_name = f're_padded_aes_key_20_{dub}_{n}.bin'
    
    # Perform CP-ABE decryption
    print('+==========================check right after enc_key_cpabe====================================+')
    cpabe_dec = os.path.join(CPABE_PATH, 'cpabe-dec')
    cpabe_sk =  PG_cpabe_sk
    SECRET_KEY_PATH = os.path.join(KEY_PATH, cpabe_sk)
    input_path = padded_key
    output2_path = os.path.join(KEY_PATH, f'Test_dec_{CT_padded_key_name}')
    subprocess.run([cpabe_dec, "-k", PUB_KEY_PATH, SECRET_KEY_PATH, input_path, "-o", output2_path])
    
    try:
        with open(output2_path, 'rb') as f:
            check_padded_dec_key = f.read()
            if check_padded_dec_key == real_padded_key:
                print('In enc_key_cpabe: correct padded_key')
                with open(temp_path, 'wb') as f:
                    f.write(check_padded_dec_key)
            else:
                print('In enc_key_cpabe: wrong padded_key')
                print(f'check_padded_dec_key: {check_padded_dec_key}')
                print(f'padded_key: {real_padded_key}')
    except:
        print(f'read file error with path: {output2_path}')
        
    # Clean up the temporary file
    os.remove(f'temp_padded_key_{dub}_{n}.bin')

    return padded_key

def main():
    for n in range (0,10):
        key_path = os.path.join(KEY_PATH, f'enc_padded_aes_key_20_{0}_{n}')
        dec_check = os.path.join(KEY_PATH, f'dec_check_enc_padded_aes_key_20_{0}_{n}')
        enc_key_cpabe(key_path, dec_check,  0, n)

if __name__ == '__main__':
    main()