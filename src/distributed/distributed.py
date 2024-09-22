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
from multiprocessing import Lock
import time
import filecmp
import multiprocessing

# Constants
ROUND = 0
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

def add_round():
    global ROUND
    ROUND += 1
    
class MJ18(ABEncMultiAuth):
    def __init__(self, groupObj, verbose=False):
        ABEncMultiAuth.__init__(self)

        self.group = groupObj
        self.start_pad_size = 16    # 128 bits
        self.end_pad_size = 16      # 128 bits
        self.aes_key_size = 32      # 256 bits

    def setup(self):
        start = time.time()

        # self.g = self.group.random(G1)
        # self.alpha = self.group.random(ZR)
        # self.beta = self.group.random(ZR)
        # self.h = self.g ** self.beta
        # self.f = self.g ** (1 / self.beta)
        # self.e_gg_alpha = pair(self.g, self.g) ** self.alpha
        # self.g_alpha = self.g ** self.alpha

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
        # aes_key = os.urandom(self.aes_key_size)
        aes_key = b'12345678901234567890123456789012'

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
        
        padded_aes_key = dec_key_cpabe_old(CT_padded_key_name, PG_cpabe_sk, "re")

        # ECC Re-encryption
        k = os.urandom(20)
        enc_k = self.elgamal.encrypt(ecc_pub_key, k)
        RE_padded_aes_key = enc_aes(padded_aes_key, k)

        end = time.time()
        rt = end - start

        return RE_padded_aes_key, enc_k, rt
    
    def parallel_reencryption(self, all_list, proxy):
        start = time.time()
        groupObj = ECGroup(prime192v2)

        # Step 1: Split all_list into chunks based on proxy count
        chunk_size = len(all_list) // proxy

        # Step 2: Use multiprocessing Manager to handle parallel processes
        manager = multiprocessing.Manager()
        return_dict = manager.dict()
        processes = []

        # Step 3: Create parallel processes for re-encryption, with an identifier (index)
        for i in range(proxy):
            # Fetch corresponding chunks from all_list
            chunk = {key: all_list[key] for key in list(all_list.keys())[i * chunk_size:(i + 1) * chunk_size]}
            
            # Start parallel processes
            lock = Lock()
            p = multiprocessing.Process(target=self._reencrypt_chunk, 
                                        args=(chunk, i, return_dict, lock))
            processes.append(p)
            p.start()

        # Step 4: Wait for all processes to finish
        for p in processes:
            p.join()
                
        for i in return_dict.keys():
            all_list[i]['RE_padded_aes_key'] = return_dict[i]['RE_padded_aes_key']
            all_list[i]['enc_k'] = {
                'c1': groupObj.deserialize(return_dict[i]['enc_k']['c1']),
                'c2': groupObj.deserialize(return_dict[i]['enc_k']['c2'])
            }

        end = time.time()
        parallellpre_time = end - start

        return all_list, parallellpre_time

    def _reencrypt_chunk(self, chunk, proxy_id, return_dict, lock):
        try:
            groupObj = ECGroup(prime192v2)
            elgamal = ElGamal(groupObj)
            reencryption_time = 0

            for i in chunk.keys():
                start = time.time()

                CT_padded_key_name = chunk[i]['CT_padded_key_name']
                ecc_pub_key = chunk[i]['ecc_pub_key']

                # CP-ABE Decryption to get padded AES key
                # This part is the broken one for parallel (padded_aes_key)
                padded_aes_key = dec_key_cpabe(CT_padded_key_name, PG_cpabe_sk, "re", lock)

                # Check if decryption failed
                if not padded_aes_key:
                    print(f"Decryption failed for chunk_id: {i}")
                    continue
                
                # Generate random key and encrypt it using ElGamal with the ECC public key
                k = b'12345678901234567890'
                enc_k = elgamal.encrypt(ecc_pub_key, k)
                print('***************** encryption aes(k of ecc) for Repadded_aes_key *****************')
                RE_padded_aes_key = enc_aes(padded_aes_key, k)

                end = time.time()
                reencryption_time += (end - start)

                # Append results with the chunk_id for proper sorting later
                return_dict[i] = {
                    'RE_padded_aes_key': RE_padded_aes_key,
                    'enc_k': {
                        'c1': groupObj.serialize(enc_k['c1']),
                        'c2': groupObj.serialize(enc_k['c2'])
                    }
                }

            # Store results in return_dict for the parallel process to collect later
            print(f"Proxy {proxy_id + 1} re-encryption done")

        except Exception as e:
            print(f"Error in _reencrypt_chunk for proxy_id {proxy_id}: {str(e)}")
            return_dict[proxy_id] = {
                'results': [],
                'reencryption_time': 0
            }

    def decryption2(self, CT_EHR, RE_padded_aes_key, enc_k, ecc_pub_key, ecc_priv_key):
        start = time.time()
        print(f'\n ========================================================> Decryption 2')

        # Step 1: decrypt padded AES KEY with ECC private key
        k = self.elgamal.decrypt(ecc_pub_key, ecc_priv_key, enc_k)

        print('-------------------Decryption aes for RE_padded_aes_key-------------------')
        padded_aes_key = dec_aes(RE_padded_aes_key, k)
        
        # try with temp_padded_key
        # temp_path = os.path.join(KEY_PATH, f'temp_padded_key_0_{ROUND}.bin')
        # print(f'temp_path: {temp_path}')
        # with open(temp_path, 'rb') as f:
        #     check_padded_dec_key = f.read()
        #     if check_padded_dec_key == padded_aes_key:
        #         print('In decryption2: correct padded_key')
        #     else:
        #         print('In decryption2: wrong padded_key')
        
        # Step 2: Unpad AES KEY and decrypt file with unpadded AES KEY
        aes_key = unpad_aes_key(padded_aes_key, self.start_pad_size, self.end_pad_size)
        #aes_key = unpad_aes_key(check_padded_dec_key, self.start_pad_size, self.end_pad_size)

        # Step 3: decrypt CT EHR using AES key
        print('-------------------Decryption aes for CT_EHR-------------------')
        EHR = dec_aes(CT_EHR, aes_key)

        end = time.time()
        rt = end - start

        return EHR, rt

def enc_aes(m, key):
    symmetric_key = SymmetricCryptoAbstraction(key)
    CT = symmetric_key.encrypt(m)
    
    print(f'\nenc_aes m: {m}')
    print(f'enc_aes CT: {CT}')
    print(f'enc_aes key: {key}')

    return CT

def dec_aes(CT, key):
    symmetric_key = SymmetricCryptoAbstraction(key)
    m = symmetric_key.decrypt(CT)
    
    print('\n-------------------Decryption aes-------------------')
    print(f'dec_aes m: {m}')
    print(f'dec_aes CT: {CT}')
    print(f'dec_aes key: {key}')
    return m

def pad_aes_key(aes_key, start_pad_size, end_pad_size):
    # start_padding = os.urandom(start_pad_size)  
    # end_padding = os.urandom(end_pad_size)      
    start_padding = b'1234567890123456'
    end_padding = b'1234567890123456'
    
    padded_aes_key = start_padding + aes_key + end_padding
    return padded_aes_key

def unpad_aes_key(padded_aes_key, start_pad_size, end_pad_size):
    aes_key = padded_aes_key[start_pad_size : -end_pad_size]

    return aes_key

def enc_key_cpabe(padded_key, policy, file_size, cpabe_pk, dub, n):
    # Write the padded key to a temporary file
    print('check padded_key 1: ', padded_key)
    temp_path = os.path.join(KEY_PATH, f'temp_padded_key_{dub}_{n}.bin')
    with open(temp_path, 'wb') as f:
        f.write(padded_key)
    
    # Use the CP-ABE Docker image to encrypt the key
    cpabe_enc = os.path.join(CPABE_PATH,'cpabe-enc')
    CT_padded_key_name = "enc_padded_aes_key_" + str(file_size) + "_" + str(dub) + "_" + str(n)
    output_path = os.path.join(KEY_PATH, CT_padded_key_name)

    # Perform CP-ABE encryption
    subprocess.run([cpabe_enc, '-k', cpabe_pk, temp_path, policy, '-o', output_path], check=True)
    
    # Perform CP-ABE decryption
    print('+==========================check right after enc_key_cpabe====================================+')
    cpabe_dec = os.path.join(CPABE_PATH, 'cpabe-dec')
    cpabe_sk =  PG_cpabe_sk
    SECRET_KEY_PATH = os.path.join(KEY_PATH, cpabe_sk)
    input_path = output_path
    output2_path = os.path.join(KEY_PATH, f'dec_{CT_padded_key_name}')
    subprocess.run([cpabe_dec, "-k", PUB_KEY_PATH, SECRET_KEY_PATH, input_path, "-o", output2_path])
    try:
        with open(output2_path, 'rb') as f:
            check_padded_dec_key = f.read()
            if check_padded_dec_key == padded_key:
                print('In enc_key_cpabe: correct padded_key')
                with open(temp_path, 'wb') as f:
                    f.write(check_padded_dec_key)
            else:
                print('In enc_key_cpabe: wrong padded_key')
    except:
        print(f'read file error with path: {output2_path}')
    
    # Clean up the temporary file
    # os.remove(f'temp_padded_key_{dub}_{n}.bin')

    return CT_padded_key_name

def dec_key_cpabe_old(CT_padded_key_name, cpabe_sk, mode):
    # CPABE & PK path
    cpabe_dec = os.path.join(CPABE_PATH, 'cpabe-dec')
    SECRET_KEY_PATH = os.path.join(KEY_PATH, cpabe_sk) 

    # Input path (CT_padded_key)
    input_path = os.path.join(KEY_PATH, CT_padded_key_name)

    # Output path (padded_key)
    prefix = "enc_padded_aes_key_"
    file_size = CT_padded_key_name[len(prefix):]
    if mode == "dec":
        padded_key_name = "dec_padded_aes_key_" + str(file_size)
    elif mode == "re":
        padded_key_name = "dec_re_padded_aes_key_" + str(file_size)
    output_path = os.path.join(KEY_PATH, padded_key_name)

    # Perform CP-ABE decryption
    subprocess.run([cpabe_dec, "-k", PUB_KEY_PATH, SECRET_KEY_PATH, input_path, "-o", output_path])
    
    # Read the padded_key to return
    try:
        with open(output_path, 'rb') as f:
            padded_aes_key = f.read()
    except:
        print(f'read file error with path: {output_path}')

    return padded_aes_key
    
def dec_key_cpabe(CT_padded_key_name, cpabe_sk, mode, lock):
    cpabe_dec = os.path.join(CPABE_PATH, 'cpabe-dec')
    SECRET_KEY_PATH = os.path.join(KEY_PATH, cpabe_sk) 

    # Input path (CT_padded_key)
    input_path = os.path.join(KEY_PATH, CT_padded_key_name)
    n = ROUND
    #input_path = os.path.join(KEY_PATH, f'temp_padded_key_0_{n}.bin')

    # Output path (padded_key)
    prefix = "enc_padded_aes_key_"
    suffix = CT_padded_key_name[len(prefix):]
    if mode == "dec":
        padded_key_name = f"dec_padded_aes_key_{suffix}"
    elif mode == "re":
        padded_key_name = f"dec_re_padded_aes_key_{suffix}"
    output_path = os.path.join(KEY_PATH, padded_key_name)

    subprocess.run([cpabe_dec, "-k", PUB_KEY_PATH, SECRET_KEY_PATH, input_path, "-o", output_path], check=True)

    # Use the lock to ensure exclusive access to the file
    with lock:
        try:
            print(f'+==========================check right after dec_key_cpabe====================================+')
            temp_path = os.path.join(KEY_PATH, f'temp_padded_key_0_{n}.bin')
            print(f'temp_path: {temp_path}')
            with open(output_path, 'rb') as f:
                padded_aes_key = f.read()
            with open(temp_path, 'rb') as f:
                check_padded_dec_key = f.read()
                add_round()
            if padded_aes_key == check_padded_dec_key:
               print('In dec_key_cpabe: correct padded_key')
            else:
               print('In dec_key_cpabe: wrong padded_key')
               print (f'padded_aes_key: {padded_aes_key}')
               print (f'check_padded_dec_key: {check_padded_dec_key}')
        except Exception as e:
            print(f"Error reading decrypted key file: {str(e)}")
            return None
        
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
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        print(f'input file: {f1.read()}, \noutput file: {f2.read()}')
    
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
        with open(f'../sample/input_distributed/input_file_{size}_{n+1}.bin', 'wb') as f:
            f.write(os.urandom(size))
        n += 1
    print(f'Create test file with size {size}: done')

def main():
    groupObj = PairingGroup('SS512')
    file_sizes = [20, 50_000, 100_000, 200_000, 400_000, 800_000, 1_600_000]
    # duplicate = [10, 100, 1000, 10000, 100000]
    # duplicate = [10, 100, 500]
    duplicate = [10]
    seq = 1
    input_file_dir = '../sample/input_distributed/'
    output_file_dir = '../sample/output_distributed/'
    output_txt = './ssxehr_parallel.txt'
    
    file_size_select, proxy = distributed_test()
    create_test_files(file_sizes, file_size_select, duplicate[0])
    
    all_list = {}
        
    # CT_EHR_dict = []
    # CT_padded_key_name_dict = []
    # ecc_pub_key_dict = []
    # ecc_priv_key_dict = []
    
    # EHR_output1 = []

    with open(output_txt, 'w+', encoding='utf-8') as f:
        f.write('{:10} {:10} {:20} {:20}\n'.format(
            'File Size', 'File amount', 'PREAveTime', 'ParallelPREAveTime'
        ))

        for dup in range(len(duplicate)):
            ssxehr = MJ18(groupObj)
            total_pre_time, pre_tot, parallellpre_tot = 0.0, 0.0, 0.0

            for round in range(seq):
                #---ENCRYPT---#
                file_size = file_sizes[file_size_select - 1]
                print(f'\nFile size: {file_size} bytes, seq: {round + 1}, duplicate: {duplicate[dup]}')
                
                # Prepare the decrypted file
                for n in range(duplicate[dup]):

                    input_file = f'{input_file_dir}input_file_{file_size}_{n+1}.bin'
                    with open(input_file, 'rb') as f_in:
                        EHR = f_in.read()

                    # 1. Setup
                    set_time = ssxehr.setup()

                    # 2. Key Generation
                    ecc_pub_key, ecc_priv_key, aes_key, cpabe_pk, cpabe_sk, key_time = ssxehr.keygen(file_size, dup, n)

                    # 3. Encryption
                    policy = "((A and B) or (C and D)) and E"
                    CT_EHR, CT_padded_key_name, enc_time = ssxehr.encryption(EHR, aes_key, cpabe_pk, policy, file_size, dup, n)
                    
                    # 4. Concat all required element
                    all_list[n] = {'CT_EHR': CT_EHR, 'CT_padded_key_name': CT_padded_key_name, 'ecc_pub_key': ecc_pub_key, 'ecc_priv_key': ecc_priv_key, 'RE_padded_aes_key':'', 'enc_k':''}
                    
                                               
                    # 5. Re-encryption
                    # RE_padded_aes_key, enc_k, pre_time = ssxehr.reencryption(CT_padded_key_name, ecc_pub_key)
                    
                    # 6 check decrypt 2 for non-parallell
                    # EHR, dec2_time = ssxehr.decryption2(CT_EHR, RE_padded_aes_key, enc_k, ecc_pub_key, ecc_priv_key)
                    
                    # output_file = f'{output_file_dir}output_file_{file_size}_{n+1}.bin'
                    # with open(output_file, 'wb') as f_out:
                    #     f_out.write(EHR)
                    # input_file = f'{input_file_dir}input_file_{file_size}_{n+1}.bin'
                    # print(f' input file: {input_file}, output file: {output_file}')
                    # if compare_files(input_file, output_file):
                    #     print(f'          File decryption 2 ✅✅successful✅✅ file size: {file_size}')
                    # else:
                    #     print(f'          File decryption 2 ❌❌failed❌❌ file size: {file_size}')
                    
                    # pre_tot += pre_time
                
                # 7.1 Re-encryption parallel
                all_list, parallellpre_time = ssxehr.parallel_reencryption(all_list, proxy)
                
                # 8. Decryption 2
                # Extract necessary information directly from all_list
                EHR_output2 = []
                # print(f'All list: {all_list}')
                
                for n in range(duplicate[dup]):
                    # Access the required elements from all_list
                    print(f'len of all_list: {len(all_list)}')
                    ct_ehr = all_list[n]['CT_EHR']
                    enc_k = all_list[n]['enc_k']
                    re_padded_aes_key = all_list[n]['RE_padded_aes_key']
                    priv_key = all_list[n]['ecc_priv_key']  # Assuming 'ecc_priv_key' is added to all_list
                    pub_key = all_list[n]['ecc_pub_key']
                    
                    print('\n=================================== Loop of decryption2 of paralell', n)

                    if enc_k and re_padded_aes_key and priv_key and pub_key:
                        EHR, dec2_time = ssxehr.decryption2(ct_ehr, re_padded_aes_key, enc_k, pub_key, priv_key)
                        print(f'\n +++++ check after decryption2: {n+1} \nEHR: {EHR}')
                        EHR_output2.append(EHR)
                    else:
                        print(f"Missing data for decryption for file number {n}")

                # Write the output files
                print(f'len of EHR_output2: {len(EHR_output2)}')
                for n in range(duplicate[dup]):
                    output2_file = f'{output_file_dir}output2_file_{file_size}_{n+1}.bin'
                    with open(output2_file, 'wb') as f_out:
                        f_out.write(EHR_output2[n])

                    input_file = f'{input_file_dir}input_file_{file_size}_{n+1}.bin'
                    # print(f' input file: {input_file}, output2 file: {output2_file}')
                    
                    if compare_files(input_file, output2_file):
                        print(f'          File decryption 2 ✅✅successful✅✅ file size: {file_size}')
                    else:
                        print(f'          File decryption 2 ❌❌failed❌❌ file size: {file_size}')
                    
                # Calculate time
                parallellpre_tot += parallellpre_time

                total_time = parallellpre_time
                total_pre_time += pre_tot
                print('Total pre time for this run: ', total_pre_time)
                print('Total parallel time for this run: ', total_time)

            # Write the average times for the current file size
            avg_pre_time = total_pre_time / seq
            avg_parallellpre_time = parallellpre_tot / seq

            f.write('{:10} {:10} {:20.16f} {:20.16f}\n'.format(
                file_size,
                duplicate[dup],
                avg_pre_time,
                avg_parallellpre_time
            ))

if __name__ == '__main__':
    main()
