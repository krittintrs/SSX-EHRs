import os
import filecmp
import time
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.schemes.pkenc.pkenc_elgamal85 import ElGamal
from charm.toolbox.ecgroup import ECGroup
from charm.toolbox.eccurve import prime192v2
import subprocess 
import time
import filecmp
import multiprocessing

# Constants
FILE_PATH = './file'
PLAIN_FILE_PATH = os.path.join(FILE_PATH,'plain_file')
ENC_FILE_PATH = os.path.join(FILE_PATH,'encrypted_file')
DEC_FILE_PATH = os.path.join(FILE_PATH,'decrypted_file')

KEY_PATH = "./key"
ENC_KEY_PATH = os.path.join(KEY_PATH, "encrypted_aes_key")
PUB_KEY_PATH = "./pub_key"
MASTER_KEY_PATH = "./master_key"

CPABE_PATH = './cpabe-0.11'

PG_cpabe_sk = "proxy_sk"

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

        setup_cpabe()

        end = time.time()
        rt = end - start

        return rt

    def keygen(self, file_size, dup, n):
        start = time.time()

        # ECC Key Gen
        groupObj = ECGroup(prime192v2)
        self.elgamal = ElGamal(groupObj)
        (ecc_pub_key, ecc_priv_key) = self.elgamal.keygen()

        # AES Key Gen
        key_name = "aes_key_" + str(file_size) + "_" + str(dup) + "_" + str(n)
        AES_KEY_PATH = os.path.join(KEY_PATH, key_name)
        aes_key = os.urandom(self.aes_key_size)

        with open(AES_KEY_PATH, 'wb') as f:
            f.write(aes_key)
                
        # CP-ABE Key Gen
        # ✅✅✅TODO: Make it randomly generated
        
        cpabe_pk = PUB_KEY_PATH
        cpabe_sk = "test_sk"
        test_attr = ["A", "B", "E"]
        generate_sk_cpabe(cpabe_sk, test_attr)
        
        proxy_attr = ["A","B", "C", "D", "E"]
        generate_sk_cpabe (PG_cpabe_sk,proxy_attr)

        end = time.time()
        rt = end - start

        return ecc_pub_key, ecc_priv_key, aes_key, cpabe_pk, cpabe_sk, rt

    def encryption(self, EHR, aes_key, pub_key, policy, file_size, dup, n): # file_size = name for output of cpabe enc
        start = time.time()

        # STEP 1: Encrypt the file with AES
        CT_EHR = enc_aes(EHR, aes_key)

        # STEP 2: Pad the AES key
        padded_key = pad_aes_key(aes_key, self.start_pad_size, self.end_pad_size)

        # STEP 3: Encrypt the padded AES key with CP-ABE
        CT_padded_key_name = enc_key_cpabe(padded_key, policy, file_size, pub_key, dup, n)
        
        end = time.time()
        rt = end - start

        return CT_EHR, CT_padded_key_name, rt

    def decryption1(self, CT_EHR, CT_padded_key_name, cpabe_sk, dup, n):
        start = time.time()

        # Step 1: decrypt padded AES KEY with cpabe key
        padded_aes_key = dec_key_cpabe(CT_padded_key_name, cpabe_sk, "dec", dup, n)

        # Step 2: Unpad AES KEY and decrypt file with unpadded AES KEY
        aes_key = unpad_aes_key(padded_aes_key, self.start_pad_size, self.end_pad_size)

        # Step 3: decrypt CT EHR using AES key
        EHR = dec_aes(CT_EHR, aes_key)

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
        # ✅✅✅ ADD in SET-UP TODO: add secret key generation for proxy gateway
        
        padded_aes_key = dec_key_cpabe(CT_padded_key_name, PG_cpabe_sk, "re")

        # ECC Re-encryption
        k = os.urandom(20)
        enc_k = self.elgamal.encrypt(ecc_pub_key, k)
        RE_padded_aes_key = enc_aes(padded_aes_key, k)

        end = time.time()
        rt = end - start

        return RE_padded_aes_key, enc_k, rt
    
    def parallel_reencryption(self, CT_padded_key_name_dict, ecc_pub_key_dict, proxy):
        start = time.time()

        # Step 1: Split CT_padded_key_name_dict into chunks based on proxy count
        chunk_size = len(CT_padded_key_name_dict) // proxy

        # Step 2: Use multiprocessing Manager to handle parallel processes
        manager = multiprocessing.Manager()
        return_dict = manager.dict()
        processes = []

        # Step 3: Create parallel processes for re-encryption
        for i in range(proxy):
            chunk = CT_padded_key_name_dict[i * chunk_size:(i + 1) * chunk_size]
            ecc_pub_key_chunk = ecc_pub_key_dict[i * chunk_size:(i + 1) * chunk_size]
            
            # Pass groupObj instead of self.elgamal
            p = multiprocessing.Process(target=self._reencrypt_chunk, 
                                        args=(chunk, ecc_pub_key_chunk, i, return_dict))
            processes.append(p)
            p.start()

        # Step 4: Wait for all processes to finish
        for p in processes:
            p.join()

        # Step 5: Aggregate results from return_dict
        RE_padded_aes_key_dict = []
        enc_k_dict = []
        total_reencryption_time = 0

        for i in range(proxy):
            if i not in return_dict:
                print(f"Missing result for proxy {i}")
                continue

            result = return_dict[i]
            RE_padded_aes_key_dict.extend(result['RE_padded_aes_key'])
            enc_k_dict.extend(result['enc_k'])
            total_reencryption_time += result['reencryption_time']

        end = time.time()
        parallellpre_time = end - start

        return RE_padded_aes_key_dict, enc_k_dict, parallellpre_time


    def _reencrypt_chunk(self, chunk, ecc_pub_key_chunk_serializable, proxy_id, return_dict):
        try:
            groupObj = ECGroup(prime192v2)
            elgamal = ElGamal(groupObj)

            re_padded_aes_keys = []
            enc_ks = []
            reencryption_time = 0

            # Ensure chunk and ecc_pub_key_chunk_serializable are of equal size
            assert len(chunk) == len(ecc_pub_key_chunk_serializable), f"Chunk size mismatch: {len(chunk)} vs {len(ecc_pub_key_chunk_serializable)}"
            
            for i, entry in enumerate(chunk):
                start = time.time()

                # Access dup and n directly from entry
                dup = entry['dup']
                n = entry['n']

                # CP-ABE Decryption to get padded AES key
                padded_aes_key = dec_key_cpabe(entry['CT_padded'], PG_cpabe_sk, "re", dup, n)

                # Add a debug statement to check the public key chunk
                if i >= len(ecc_pub_key_chunk_serializable):
                    print(f"Missing public key for chunk {i}")
                    continue
                
                print(f"Processing chunk {i} with public key: {ecc_pub_key_chunk_serializable[i]}")
                
                # Convert the serialized ecc_pub_key back to elliptic curve key
                ecc_pub_key = convert_list_to_key(ecc_pub_key_chunk_serializable[i], groupObj)

                k = os.urandom(20)
                enc_k = elgamal.encrypt(ecc_pub_key, k)
                RE_padded_aes_key = enc_aes(padded_aes_key, k)

                end = time.time()
                reencryption_time += (end - start)

                re_padded_aes_keys.append(RE_padded_aes_key)
                enc_ks.append(enc_k)

            # Store results in return_dict
            return_dict[proxy_id] = {
                'RE_padded_aes_key': re_padded_aes_keys,
                'enc_k': enc_ks,
                'reencryption_time': reencryption_time
            }
        except Exception as e:
            print(f"Error in _reencrypt_chunk for proxy_id {proxy_id}: {str(e)}")
            return_dict[proxy_id] = {
                'RE_padded_aes_key': [],
                'enc_k': [],
                'reencryption_time': 0
            }

    def decryption2(self, CT_EHR, RE_padded_aes_key, enc_k, ecc_pub_key, ecc_priv_key):
        start = time.time()

        # Step 1: decrypt padded AES KEY with ECC private key
        k = self.elgamal.decrypt(ecc_pub_key, ecc_priv_key, enc_k)
        print(f'k: {k} / {type(k)}')
        padded_aes_key = dec_aes(RE_padded_aes_key, k)

        # Step 2: Unpad AES KEY and decrypt file with unpadded AES KEY
        aes_key = unpad_aes_key(padded_aes_key, self.start_pad_size, self.end_pad_size)

        # Step 3: decrypt CT EHR using AES key
        EHR = dec_aes(CT_EHR, aes_key)

        end = time.time()
        rt = end - start

        return EHR, rt

def enc_aes(m, key):
    symmetric_key = SymmetricCryptoAbstraction(key)
    CT = symmetric_key.encrypt(m)
    return CT

def dec_aes(CT, key):
    symmetric_key = SymmetricCryptoAbstraction(key)
    m = symmetric_key.decrypt(CT)
    return m

def pad_aes_key(aes_key, start_pad_size, end_pad_size):
    start_padding = os.urandom(start_pad_size)  
    end_padding = os.urandom(end_pad_size)      
    
    padded_aes_key = start_padding + aes_key + end_padding
    return padded_aes_key

def unpad_aes_key(padded_aes_key, start_pad_size, end_pad_size):
    aes_key = padded_aes_key[start_pad_size : -end_pad_size]

    return aes_key

def enc_key_cpabe(padded_key, policy, file_size, cpabe_pk, dub, n):
    # Write the padded key to a temporary file
    with open('temp_padded_key.bin', 'wb') as f:
        f.write(padded_key)
    
    # Use the CP-ABE Docker image to encrypt the key
    cpabe_enc = os.path.join(CPABE_PATH,'cpabe-enc')
    CT_padded_key_name = "enc_padded_aes_key_" + str(file_size) + "_" + str(dub) + "_" + str(n)
    output_path = os.path.join(KEY_PATH, CT_padded_key_name)

    # Perform CP-ABE encryption
    subprocess.run([cpabe_enc, '-k', cpabe_pk, 'temp_padded_key.bin', policy, '-o', output_path], check=True)
    
    # Clean up the temporary file
    os.remove('temp_padded_key.bin')

    return CT_padded_key_name

def dec_key_cpabe(CT_padded_key_name, cpabe_sk, mode, dup, n):
    # CPABE & PK path
    cpabe_dec = os.path.join(CPABE_PATH, 'cpabe-dec')
    SECRET_KEY_PATH = os.path.join(KEY_PATH, cpabe_sk) 

    # Input path (CT_padded_key)
    input_path = os.path.join(KEY_PATH, CT_padded_key_name)

    # Output path (padded_key)
    prefix = "enc_padded_aes_key_"
    file_size = CT_padded_key_name[len(prefix):]
    if mode == "dec":
        padded_key_name = "dec_padded_aes_key_" + str(file_size) + "_" + str(dup) + "_" + str(n)
    elif mode == "re":
        padded_key_name = "dec_re_padded_aes_key_" + str(file_size) + "_" + str(dup) + "_" + str(n)
    output_path = os.path.join(KEY_PATH, padded_key_name)

    # Perform CP-ABE decryption
    subprocess.run([cpabe_dec, "-k", PUB_KEY_PATH, SECRET_KEY_PATH, input_path, "-o", output_path])
    
    # Read the padded_key to return
    try:
        with open(output_path, 'rb') as f:
            padded_aes_key = f.read()
    except:
        print('''
              🚨🚨🚨🚨🚨🚨🚨🚨🚨
               ⛔⛔⛔ERROR⛔⛔⛔
              🚨🚨🚨🚨🚨🚨🚨🚨🚨''')

    return padded_aes_key

def setup_cpabe():
    cpabe_setup_path = os.path.join(CPABE_PATH, 'cpabe-setup')
    subprocess.run([cpabe_setup_path], check=True)

def generate_sk_cpabe(sk_name, proxy_attr):
    sk_path = os.path.join(KEY_PATH, sk_name)
    cpabe_keygen_path = os.path.join(CPABE_PATH, 'cpabe-keygen')
    subprocess.run([cpabe_keygen_path, '-o', sk_path, PUB_KEY_PATH, MASTER_KEY_PATH] + proxy_attr, check=True)
    
def convert_list_to_key(key_list, groupObj):
    # Assuming key_list is [x, y] where x, y are the coordinates of the public key point
    # Reconstructing the ECC public key using groupObj (this may vary depending on your library)
    ecc_pub_key = groupObj.init(G1, [key_list[0], key_list[1]])
    return ecc_pub_key

def convert_list_to_key(key_list, groupObj):
    # Assuming key_list is [x, y] where x, y are the coordinates of the public key point
    # Reconstructing the ECC public key using groupObj (this may vary depending on your library)
    ecc_pub_key = groupObj.init(G1, [key_list[0], key_list[1]])
    return ecc_pub_key

#========================= MAIN ===========================#

def compare_files(file1, file2):
    return filecmp.cmp(file1, file2, shallow=False)

def distributed_test():
    # Prepare the input file for parralel execution
    file_size_select = int(input("""Enter the file size
                          1. 50 KB
                          2. 100 KB
                          3. 200 KB
                          4. 400 KB
                          5. 800 KB
                          6. 1.6 MB
                          :"""))
    proxy = int(input("Enter the proxy number: "))
    
    return file_size_select, proxy

def create_test_files(file_sizes, file_size_select, duplicate):
    for n in range(duplicate):
        size = file_sizes[file_size_select - 1]
        with open(f'../sample/input_distributed/input_file_{size}_{n}.bin', 'wb') as f:
            f.write(os.urandom(size))
        n += 1
    print(f'Create test file with size {size}: done')

def main():
    groupObj = PairingGroup('SS512')
    file_sizes = [50_000, 100_000, 200_000, 400_000, 800_000, 1_600_000]
    duplicate = [10, 100, 1000, 10000, 100000]
    seq = 5
    input_file_dir = '../sample/input_distributed/'
    output_file_dir = '../sample/output_distributed/'
    output_txt = './ssxehr_parallel.txt'
    
    file_size_select, proxy = distributed_test()
    create_test_files(file_sizes, file_size_select, duplicate[1])\
        
    CT_EHR_dict = []
    CT_padded_key_name_dict = []
    ecc_pub_key_dict = []
    ecc_priv_key_dict = []
    # ssxehr_elgamal_dict = []

    with open(output_txt, 'w+', encoding='utf-8') as f:
        f.write('{:7} {:18} {:18}\n'.format(
            'Duplicate', 'PREAveTime', 'ParallelPREAveTime'
        ))

        for dup in range(len(duplicate)):
            ssxehr = MJ18(groupObj)
            pre_tot, parallellpre_tot = 0.0, 0.0

            for round in range(seq):
                #---ENCRYPT---#
                file_size = file_sizes[file_size_select - 1]
                print(f'\nFile size: {file_size} bytes, seq: {round + 1}, duplicate: {duplicate[dup]}')
                
                # prepare the decrypted file
                
                for n in range(duplicate[dup]):

                    input_file = f'{input_file_dir}input_file_{file_size}_{n}.bin'
                    with open(input_file, 'rb') as f_in:
                        EHR = f_in.read()

                    # 1. Setup
                    set_time = ssxehr.setup()

                    # 2. Key Generation
                    ecc_pub_key, ecc_priv_key, aes_key, cpabe_pk, cpabe_sk, key_time = ssxehr.keygen(file_size, dup, n)
                    ecc_pub_key_dict.append({'n': n, 'ecc_pub_key': ecc_pub_key})
                    ecc_priv_key_dict.append({'n': n, 'ecc_priv_key': ecc_priv_key})
                    # ssxehr_elgamal_dict.append({'n': n, 'elgamal': ssxehr.elgamal})

                    # 3. Encryption
                    policy = "((A and B) or (C and D)) and E"
                    CT_EHR, CT_padded_key_name, enc_time = ssxehr.encryption(EHR, aes_key, cpabe_pk, policy, file_size, dup, n)
                    CT_EHR_dict.append({'n': n, 'CT_EHR': CT_EHR})
                    # Inside the loop where encryption happens
                    CT_padded_key_name_dict.append({'n': n, 'dup': dup, 'CT_padded': CT_padded_key_name})

                    
                # 7.1 Re-encryption parallel
                print (CT_padded_key_name_dict)
                RE_padded_aes_key_dict, enc_k_dict, parallellpre_time = ssxehr.parallel_reencryption(CT_padded_key_name_dict, ecc_pub_key_dict, proxy)
                
                # 8. Decryption 2
                EHR_output2, dec2_time = ssxehr.decryption2(CT_EHR_dict, RE_padded_aes_key_dict, enc_k_dict, ecc_pub_key_dict, ecc_priv_key_dict)

                # Output file       
                output2_file = f'{output_file_dir}output_file2_{file_size}_{j}.bin'
                with open(output2_file, 'wb') as f_out:
                    f_out.write(EHR_output2)

                # Compare the original file with the decrypted file
                if compare_files(input_file, output2_file):
                    print(f'          File decryption 2 ✅✅successful✅✅ file size: {file_size}')
                else:
                    print(f'          File decryption 2 ❌❌failed❌❌ file size: {file_size}')
                    
                # Calculate time
                # pre_tot += pre_time
                parallellpre_tot += parallellpre_time

                # total_time = pre_time + parallellpre_time
                total_time = parallellpre_time
                print('Total time for this run: ', total_time)

            # Write the average times for the current file size
            avg_pre_time = pre_tot / seq
            avg_parallellpre_time = parallellpre_tot / seq

            out0 = str(file_size).zfill(7)
            out1 = str(format(avg_pre_time, '.16f'))
            out2 = str(format(avg_parallellpre_time, '.16f'))

            f.write(f'{out0} {out1} {out2}\n')



if __name__ == '__main__':
    main()
