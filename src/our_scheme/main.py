import os
import filecmp
import time
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import subprocess 
import time
import filecmp

# Constants
AES_KEY_SIZE = 32   # AES-256 

FILE_PATH = './file'
PLAIN_FILE_PATH = os.path.join(FILE_PATH,'plain_file')
ENC_FILE_PATH = os.path.join(FILE_PATH,'encrypted_file')
DEC_FILE_PATH = os.path.join(FILE_PATH,'decrypted_file')

KEY_PATH = "./key"
ENC_KEY_PATH = os.path.join(KEY_PATH, "encrypted_aes_key")
PUB_KEY_PATH = os.path.join(KEY_PATH, "pub_key")
MASTER_KEY_PATH = os.path.join(KEY_PATH, "master_key")

CPABE_PATH = './cpabe-0.11'

class MJ18(ABEncMultiAuth):
    def __init__(self, groupObj, verbose=False):
        ABEncMultiAuth.__init__(self)

        self.group = groupObj
        self.start_pad_size = 16     # 128 bits
        self.end_pad_size = 16       # 128 bits

    def setup(self):
        start = time.time()

        self.g = self.group.random(G1)
        self.alpha = self.group.random(ZR)
        self.beta = self.group.random(ZR)
        self.h = self.group.exp(self.g, self.beta)
        self.f = self.group.exp(self.g, 1 / self.beta)
        self.e_gg_alpha = self.group.pair(self.g, self.g) ** self.alpha
        self.g_alpha = self.group.exp(self.g, self.alpha)

        end = time.time()
        rt = end - start

        return rt

    def keygen(self):
        start = time.time()

        # ECC Key Gen
        priv_key = self.group.random(ZR)
        base_point = self.group.random(G1)
        pub_key = priv_key * base_point

        # AES Key Gen

        end = time.time()
        rt = end - start

        return priv_key, pub_key, aes_key, rt

    def encryption(self, EHR, aes_key, pub_key, policy, name): # name for output of cpabe enc
        start = time.time()

        # STEP 1: Encrypt the file with AES
        CT_EHR, enc_file_time = enc_file_aes(EHR, aes_key)

        # STEP 2: Pad the AES key
        padded_key = pad_aes_key(aes_key, self.start_pad_size, self.end_pad_size)

        # STEP 3: Encrypt the padded AES key with CP-ABE
        CT_padded_key_name, enc_aes_key_time = enc_key_cpabe(padded_key, policy, name, pub_key)
        
        end = time.time()
        rt = end - start
        
        print(f'''
            ========================================================
            Time that use for ENCRYPT --- {name} file --- is 
            
            TOTAL ENC TIME    =>  {rt} secs
            ENC FILE TIME     =>  {enc_file_time} secs
            ENC AES KEY TIME  =>  {enc_aes_key_time} secs
            --------------------------------------------------------''')
        
        return CT_EHR, CT_padded_key_name, rt
    
    def reencryption(self):
        start = time.time()

        end = time.time()
        rt = end - start

        return rt

    def decryption1(self, CT_EHR, CT_padded_key_name):
        start = time.time()

        # Step 1: decrypt padded AES KEY with cpabe key
        priv_key = "test_priv"
        padded_aes_key, dec_aes_key_time = dec_key_cpabe(CT_padded_key_name, priv_key)

        # Step 2: Unpad AES KEY and decrypt file with unpadded AES KEY
        aes_key = unpad_aes_key(padded_aes_key)
        EHR, dec_file_time = dec_file_aes(CT_EHR, aes_key)

        end = time.time()
        rt = end - start

        return EHR, rt
    
    def decryption2(self):
        start = time.time()

        end = time.time()
        rt = end - start

        return rt
    
def generate_aes_key(name):
    key_name = "aes_key_" + name
    AES_KEY_PATH = os.path.join(KEY_PATH,key_name)
    aes_key = os.urandom(AES_KEY_SIZE)

    with open(AES_KEY_PATH, 'wb') as f:
        f.write(aes_key)

    return aes_key

def enc_file_aes(plaintext, key):
    start = time.time()
    # Ensure the key size is correct (32 bytes for AES-256)
    if len(key) != AES_KEY_SIZE:
        raise ValueError("Key must be 32 bytes long for AES-256.")
    
    # Initialize the symmetric encryption abstraction with AES
    symmetric_key = SymmetricCryptoAbstraction(key)
    CT = symmetric_key.encrypt(plaintext)
    
    end = time.time()
    rt = end - start

    return CT, rt

def dec_file_aes(CT_EHR, key):
    start = time.time()

    # Ensure the key size is correct (32 bytes for AES-256)
    if len(key) != AES_KEY_SIZE:
        raise ValueError("Key must be 32 bytes long for AES-256.")

    symmetric_key = SymmetricCryptoAbstraction(key)
    EHR = symmetric_key.decrypt(CT_EHR)
    
    end = time.time()
    rt = end - start

    return EHR, rt

def pad_aes_key(key, start_pad_size, end_pad_size):
    start_padding = os.urandom(start_pad_size)  
    end_padding = os.urandom(end_pad_size)      
    
    padded_key = start_padding + key + end_padding
    return padded_key

def unpad_aes_key(padded_aes_key, start_pad_size, end_pad_size):
    unpadded_aes_key = padded_aes_key[start_pad_size : -end_pad_size]

    return unpadded_aes_key

def enc_key_cpabe(padded_key, policy, name, pub_key):
    start = time.time()

    # Write the padded key to a temporary file
    with open('temp_padded_key.bin', 'wb') as f:
        f.write(padded_key)
    
    # Use the CP-ABE Docker image to encrypt the key
    cpabe_enc = os.path.join(CPABE_PATH,'cpabe-enc')
    CT_padded_key_name = "enc_padded_aes_key_" + name
    output_path = os.path.join(KEY_PATH, CT_padded_key_name)

    # Perform CP-ABE encryption
    subprocess.run([cpabe_enc, '-k', pub_key, 'temp_padded_key.bin', policy, '-o', output_path], check=True)
    
    # Clean up the temporary file
    os.remove('temp_padded_key.bin')

    end = time.time()
    rt = end - start

    return CT_padded_key_name, rt

def dec_key_cpabe(CT_padded_key_name, priv_key):
    start = time.time()

    # CPABE & PK path
    cpabe_dec = os.path.join(CPABE_PATH, 'cpabe-dec')
    PRIV_KEY_PATH = os.path.join(KEY_PATH, priv_key) 

    # Input path (CT_padded_key)
    input_path = os.path.join(KEY_PATH, CT_padded_key_name)

    # Output path (padded_key)
    prefix = "enc_padded_aes_key_"
    name = CT_padded_key_name[len(prefix):]
    padded_key_name = "dec_padded_aes_key_" + name
    output_path = os.path.join(KEY_PATH, padded_key_name)

    # Perform CP-ABE decryption
    subprocess.run([cpabe_dec, "-k", PUB_KEY_PATH, PRIV_KEY_PATH, input_path, "-o", output_path])
    
    # Read the padded_key to return
    with open(padded_key_name, 'rb') as f:
        padded_aes_key = f.read()

    end = time.time()
    rt = end - start

    return padded_aes_key, rt

def compare_files(file1, file2):
    return filecmp.cmp(file1, file2, shallow=False)

#========================= MAIN ===========================#

def main():
    groupObj = PairingGroup('SS512')
    file_sizes = [50_000, 100_000, 200_000, 400_000, 800_000, 1_600_000]
    seq = 5
    input_file_dir = '../sample/input/'
    output_file_dir = '../sample/output/'
    output_txt = './our.txt'

    with open(output_txt, 'w+', encoding='utf-8') as f:
        f.write('{:7} {:18} {:18} {:18} {:18} {:18} {:18}\n'.format(
            'Size', 'EncAveTime', 'AesEncAveTime', 'CpabeAveTime', '??TIME', 'PREAveTime', 'DecAveTime'
        ))

        for i in range(len(file_sizes)):
            ssxehr = MJ18(groupObj)
            set_tot, key_tot, enc_tot, dec1_tot, pre_tot, dec2_tot = 0.0, 0.0, 0.0, 0.0, 0.0, 0.0

            for j in range(seq):
                #---ENCRYPT---#
                file_size = file_sizes[i]
                print(f'\nFile size: {file_size} bytes, seq: {j}')

                name = str(file_size) + "bytes"
                policy = "((A and B) or (C and D)) and E"
                
                aes_key = generate_aes_key(name)
                pub_key = PUB_KEY_PATH

                input_file = f'{input_file_dir}input_file_{file_size}_{j}.bin'
                with open(input_file, 'rb') as f_in:
                    EHR = f_in.read()

                # 1. Setup
                set_time = ssxehr.setup()

                # 2. Key Generation
                key_time = ssxehr.keygen()

                # 3. Encryption
                CT_EHR, CT_padded_key_name, enc_time = ssxehr.encryption(EHR, aes_key, pub_key, policy, name)
                
                # 4. Re-encryption
                pre_time = ssxehr.reencryption()

                # 5. Decryption 1
                EHR_output1, dec1_time = ssxehr.decryption1(name, CT_EHR, CT_padded_key_name)
                
                # 6. Decryption 2
                dec2_time = ssxehr.decryption2()

                # Output file
                output_file = f'{output_file_dir}output_file_{file_size}_{j}.bin'
                with open(output_file, 'wb') as f_out:
                    f_out.write(EHR_output1)

                # Compare the original file with the decrypted file
                if compare_files(input_file, output_file):
                    print(f'          File decryption ✅✅successful✅✅ file size: {name}')
                else:
                    print(f'          File decryption ❌❌failed❌❌ file size: {name}')
                    
                # Calculate time
                set_tot += set_time
                key_tot += key_time
                enc_tot += enc_time
                pre_tot += pre_time
                dec1_tot += dec1_time
                dec2_tot += dec2_time

                total_time = set_time + key_time + enc_time + pre_time + dec1_time + dec2_time
                print('Total time for this run: ', total_time)

            # Write the average times for the current file size
            avg_set_time = set_tot / seq
            avg_key_time = key_tot / seq
            avg_enc_time = enc_tot / seq
            avg_pre_time = pre_tot / seq
            avg_dec1_time = dec1_tot / seq
            avg_dec2_time = dec2_tot / seq

            out0 = str(file_sizes[i]).zfill(7)
            out1 = str(format(avg_set_time, '.16f'))
            out2 = str(format(avg_key_time, '.16f'))
            out3 = str(format(avg_enc_time, '.16f'))
            out4 = str(format(avg_pre_time, '.16f'))
            out5 = str(format(avg_dec1_time, '.16f'))
            out6 = str(format(avg_dec2_time, '.16f'))

            f.write(f'{out0} {out1} {out2} {out3} {out4} {out5} {out6}\n')

if __name__ == '__main__':
    main()
