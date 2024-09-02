import os
import filecmp
import time
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.core.math.integer import integer
from charm.schemes.pkenc.pkenc_elgamal85 import ElGamal
from charm.toolbox.ecgroup import ECGroup
from charm.toolbox.eccurve import prime192v2
import subprocess 
import time
import filecmp

# Constants
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
        self.start_pad_size = 16    # 128 bits
        self.end_pad_size = 16      # 128 bits
        self.aes_key_size = 32      # 256 bits

    def setup(self):
        start = time.time()

        self.g = self.group.random(G1)
        self.alpha = self.group.random(ZR)
        self.beta = self.group.random(ZR)
        self.h = self.g ** self.beta
        self.f = self.g ** (1 / self.beta)
        self.e_gg_alpha = pair(self.g, self.g) ** self.alpha
        self.g_alpha = self.g ** self.alpha

        end = time.time()
        rt = end - start

        return rt

    def keygen(self, file_size):
        start = time.time()

        # ECC Key Gen
        # Generate key pair
        groupObj = ECGroup(prime192v2)
        self.elgamal = ElGamal(groupObj)   

        # Generate key pair
        (ecc_pub_key, ecc_priv_key) = self.elgamal.keygen()

        # AES Key Gen
        key_name = "aes_key_" + str(file_size)
        AES_KEY_PATH = os.path.join(KEY_PATH, key_name)
        aes_key = os.urandom(self.aes_key_size)

        with open(AES_KEY_PATH, 'wb') as f:
            f.write(aes_key)
                
        # CP-ABE Key Gen
        # TODO: Make it randomly generated
        cpabe_pk = PUB_KEY_PATH
        cpabe_sk = "test_priv"

        end = time.time()
        rt = end - start

        return ecc_pub_key, ecc_priv_key, aes_key, cpabe_pk, cpabe_sk, rt

    def encryption(self, EHR, aes_key, pub_key, policy, file_size): # name for output of cpabe enc
        start = time.time()

        # STEP 1: Encrypt the file with AES
        CT_EHR, enc_file_time = enc_file_aes(EHR, aes_key)

        # STEP 2: Pad the AES key
        padded_key = pad_aes_key(aes_key, self.start_pad_size, self.end_pad_size)

        # STEP 3: Encrypt the padded AES key with CP-ABE
        CT_padded_key_name, enc_aes_key_time = enc_key_cpabe(padded_key, policy, file_size, pub_key)
        
        end = time.time()
        rt = end - start
        
        # print(f'''
        #     ========================================================
        #     Time that use for ENCRYPT --- {file_size} file --- is 
            
        #     TOTAL ENC TIME    =>  {rt} secs
        #     ENC FILE TIME     =>  {enc_file_time} secs
        #     ENC AES KEY TIME  =>  {enc_aes_key_time} secs
        #     --------------------------------------------------------''')
        
        # TODO: remove test
        global test_aes_key
        test_aes_key = padded_key

        return CT_EHR, CT_padded_key_name, rt

    def decryption1(self, CT_EHR, CT_padded_key_name, cpabe_sk):
        start = time.time()

        # Step 1: decrypt padded AES KEY with cpabe key
        padded_aes_key, dec_aes_key_time = dec_key_cpabe(CT_padded_key_name, cpabe_sk)

        # Step 2: Unpad AES KEY and decrypt file with unpadded AES KEY
        aes_key = unpad_aes_key(padded_aes_key, self.start_pad_size, self.end_pad_size)

        # Step 3: decrypt CT EHR using AES key
        EHR, dec_file_time = dec_file_aes(CT_EHR, aes_key)

        end = time.time()
        rt = end - start

        return EHR, rt
    
    def generate_authToken(self):
        start = time.time()

        # TODO: implement 

        end = time.time()
        rt = end - start

        return rt
    
    def verify_authToken(self):
        start = time.time()

        # TODO: implement 

        end = time.time()
        rt = end - start

        return rt
    
    def reencryption(self, CT_padded_key_name, ecc_pub_key):
        start = time.time()

        # CP-ABE Decryption
        PG_cpabe_sk = "secret key of proxy gateway"
        padded_aes_key, dec_aes_key_time = dec_key_cpabe(CT_padded_key_name, PG_cpabe_sk)

        # ECC Re-encryption
        k = os.urandom(20)
        enc_k = self.elgamal.encrypt(ecc_pub_key, k)
        RE_padded_aes_key, enc_time = enc_file_aes(padded_aes_key, k)

        print(f'\n >> RE-ENC << ')
        # print(f'padded_aes_key: {padded_aes_key}')
        print(f'k: {k} / {type(k)}')
        print(f'Length of padded_aes_key: {len(padded_aes_key)}')
        # print(f'RE_padded_aes_key: {RE_padded_aes_key}')
        print(f'Length of RE_padded_aes_key: {len(RE_padded_aes_key)}')
        # print(f'ecc_pub_key: {ecc_pub_key}')

        padded_aes_key, dec_time = dec_file_aes(RE_padded_aes_key, k)
        print(f'padded_aes_key: {padded_aes_key}')

        end = time.time()
        rt = end - start

        return RE_padded_aes_key, enc_k, rt
    
    def decryption2(self, CT_EHR, RE_padded_aes_key, enc_k, ecc_pub_key, ecc_priv_key):
        start = time.time()

        # Step 1: decrypt padded AES KEY with ECC private key
        k = self.elgamal.decrypt(ecc_pub_key, ecc_priv_key, enc_k)
        print(f'k: {k} / {type(k)}')
        padded_aes_key, dec_time = dec_file_aes(RE_padded_aes_key, k)

        # Step 2: Unpad AES KEY and decrypt file with unpadded AES KEY
        aes_key = unpad_aes_key(padded_aes_key, self.start_pad_size, self.end_pad_size)

        print(f'\n >> DEC 2 << ')
        # print(f'RE_padded_aes_key: {RE_padded_aes_key}')
        print(f'Length of RE_padded_aes_key: {len(RE_padded_aes_key)}')
        # print(f'padded_aes_key: {padded_aes_key}')
        print(f'Length of padded_aes_key: {len(padded_aes_key)}')
        print(f'aes_key: {aes_key}')
        # print(f'ecc_pub_key: {ecc_pub_key}')
        # print(f'ecc_priv_key: {ecc_priv_key}')

        # Step 3: decrypt CT EHR using AES key
        EHR, dec_file_time = dec_file_aes(CT_EHR, aes_key)

        end = time.time()
        rt = end - start

        return EHR, rt
    
def bytes_to_integer_element(byte_data):
    int_value = int.from_bytes(byte_data, byteorder='big', signed=False)
    original_length = len(byte_data)
    int_with_size = (int_value << (original_length.bit_length() + 7)) | original_length
    return integer(int_with_size)

def integer_element_to_bytes(int_elem):
    int_value = int(int_elem)
    original_length = int_value & ((1 << 8) - 1)
    hed_int = int_value >> (original_length.bit_length() + 7)
    return hed_int.to_bytes(original_length, byteorder='big', signed=False)

def enc_file_aes(m, key):
    start = time.time()

    symmetric_key = SymmetricCryptoAbstraction(key)
    CT = symmetric_key.encrypt(m)
    
    end = time.time()
    rt = end - start

    return CT, rt

def dec_file_aes(CT, key):
    start = time.time()

    symmetric_key = SymmetricCryptoAbstraction(key)
    m = symmetric_key.decrypt(CT)
    
    end = time.time()
    rt = end - start

    return m, rt

def pad_aes_key(aes_key, start_pad_size, end_pad_size):
    start_padding = os.urandom(start_pad_size)  
    end_padding = os.urandom(end_pad_size)      
    
    padded_aes_key = start_padding + aes_key + end_padding
    return padded_aes_key

def unpad_aes_key(padded_aes_key, start_pad_size, end_pad_size):
    aes_key = padded_aes_key[start_pad_size : -end_pad_size]

    return aes_key

def enc_key_cpabe(padded_key, policy, file_size, cpabe_pk):
    start = time.time()

    # Write the padded key to a temporary file
    with open('temp_padded_key.bin', 'wb') as f:
        f.write(padded_key)
    
    # Use the CP-ABE Docker image to encrypt the key
    cpabe_enc = os.path.join(CPABE_PATH,'cpabe-enc')
    CT_padded_key_name = "enc_padded_aes_key_" + str(file_size)
    output_path = os.path.join(KEY_PATH, CT_padded_key_name)

    # TODO: remove test
    # Perform CP-ABE encryption
    # subprocess.run([cpabe_enc, '-k', cpabe_pk, 'temp_padded_key.bin', policy, '-o', output_path], check=True)
    
    # Clean up the temporary file
    os.remove('temp_padded_key.bin')

    end = time.time()
    rt = end - start

    return CT_padded_key_name, rt

def dec_key_cpabe(CT_padded_key_name, cpabe_sk):
    start = time.time()

    # CPABE & PK path
    cpabe_dec = os.path.join(CPABE_PATH, 'cpabe-dec')
    SECREcT_KEY_PATH = os.path.join(KEY_PATH, cpabe_sk) 

    # Input path (CT_padded_key)
    input_path = os.path.join(KEY_PATH, CT_padded_key_name)

    # Output path (padded_key)
    prefix = "enc_padded_aes_key_"
    file_size = CT_padded_key_name[len(prefix):]
    padded_key_name = "dec_padded_aes_key_" + str(file_size)
    output_path = os.path.join(KEY_PATH, padded_key_name)

    # TODO: remove test
    # Perform CP-ABE decryption
    # subprocess.run([cpabe_dec, "-k", PUB_KEY_PATH, SECRET_KEY_PATH, input_path, "-o", output_path])
    
    # Read the padded_key to return
    # with open(padded_key_name, 'rb') as f:
    #     padded_aes_key = f.read()
    padded_aes_key = test_aes_key

    end = time.time()
    rt = end - start

    return padded_aes_key, rt

#========================= MAIN ===========================#

def compare_files(file1, file2):
    return filecmp.cmp(file1, file2, shallow=False)

def main():
    groupObj = PairingGroup('SS512')
    file_sizes = [50_000, 100_000, 200_000, 400_000, 800_000, 1_600_000]
    seq = 5
    input_file_dir = '../sample/input/'
    output_file_dir = '../sample/output/'
    output_txt = './ssxehr.txt'

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

                input_file = f'{input_file_dir}input_file_{file_size}.bin'
                with open(input_file, 'rb') as f_in:
                    EHR = f_in.read()

                # 1. Setup
                set_time = ssxehr.setup()

                # 2. Key Generation
                ecc_pub_key, ecc_priv_key, aes_key, cpabe_pk, cpabe_sk, key_time = ssxehr.keygen(file_size)

                # 3. Encryption
                policy = "((A and B) or (C and D)) and E"
                CT_EHR, CT_padded_key_name, enc_time = ssxehr.encryption(EHR, aes_key, cpabe_pk, policy, file_size)

                # 4. Decryption 1
                EHR_output1, dec1_time = ssxehr.decryption1(CT_EHR, CT_padded_key_name, cpabe_sk)

                # 5. Generate authToken
                gen_time = ssxehr.generate_authToken()

                # 6. Verify authToken
                vrf_time = ssxehr.verify_authToken()

                # 7. Re-encryption
                RE_padded_aes_key, enc_k, pre_time = ssxehr.reencryption(CT_padded_key_name, ecc_pub_key)
                
                # 8. Decryption 2
                EHR_output2, dec2_time = ssxehr.decryption2(CT_EHR, RE_padded_aes_key, enc_k, ecc_pub_key, ecc_priv_key)

                # Output file
                output1_file = f'{output_file_dir}output_file_{file_size}_{j}.bin'
                with open(output1_file, 'wb') as f_out:
                    f_out.write(EHR_output1)
                
                output2_file = f'{output_file_dir}output_file_{file_size}_{j}.bin'
                with open(output2_file, 'wb') as f_out:
                    f_out.write(EHR_output2)

                # Compare the original file with the decrypted file
                if compare_files(input_file, output1_file):
                    print(f'          File decryption 1 ✅✅successful✅✅ file size: {file_size}')
                else:
                    print(f'          File decryption 1 ❌❌failed❌❌ file size: {file_size}')
                if compare_files(input_file, output2_file):
                    print(f'          File decryption 2 ✅✅successful✅✅ file size: {file_size}')
                else:
                    print(f'          File decryption 2 ❌❌failed❌❌ file size: {file_size}')
                    
                # Calculate time
                set_tot += set_time
                key_tot += key_time
                enc_tot += enc_time
                dec1_tot += dec1_time
                pre_tot += pre_time
                dec2_tot += dec2_time

                total_time = set_time + key_time + enc_time + dec1_time + pre_time + dec2_time
                print('Total time for this run: ', total_time)

            # Write the average times for the current file size
            avg_set_time = set_tot / seq
            avg_key_time = key_tot / seq
            avg_enc_time = enc_tot / seq
            avg_dec1_time = dec1_tot / seq
            avg_pre_time = pre_tot / seq
            avg_dec2_time = dec2_tot / seq

            out0 = str(file_sizes[i]).zfill(7)
            out1 = str(format(avg_set_time, '.16f'))
            out2 = str(format(avg_key_time, '.16f'))
            out3 = str(format(avg_enc_time, '.16f'))
            out4 = str(format(avg_dec1_time, '.16f'))
            out5 = str(format(avg_pre_time, '.16f'))
            out6 = str(format(avg_dec2_time, '.16f'))

            f.write(f'{out0} {out1} {out2} {out3} {out4} {out5} {out6}\n')

if __name__ == '__main__':
    main()
