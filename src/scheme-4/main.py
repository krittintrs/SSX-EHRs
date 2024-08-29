import os
import random
import time
import numpy as np
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.hash_module import Hash
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.core.math.integer import integer
from hashlib import sha256


class MJ18(ABEncMultiAuth):
    def __init__(self, groupObj, verbose=False):
        ABEncMultiAuth.__init__(self)
        # global group, H, H1, H2, H3, H4, g

        # Initialize pairing group
        self.group = PairingGroup('SS512')
        self.H = Hash(self.group)

        # H1: {0, 1}* → Z*q
        self.H1 = lambda *args: self.H.hashToZr(''.join([str(arg) for arg in args]))

        # H2: {0, 1}* → G
        self.H2 = lambda *args: self.group.hash(''.join([str(arg) for arg in args]), G1)  # Maps to G1

        # H3: GT → {0, 1}*
        self.H3 = lambda x: self.H.hashToZn(x)  # Maps GT to {0, 1}
        
        # H4: {0, 1}* → {0, 1}*
        self.H4 = lambda *args: sha256(''.join([str(arg) for arg in args]).encode()).digest()  # Maps {0, 1}* to {0, 1}*

        self.g = self.group.random(G1)
        self.s = self.group.random(ZR)
        self.Tc = time.time()
        self.Serv = 'IIoT service X'
        self.omega = self.H1(self.Serv, self.s, self.Tc)
        self.W = self.g ** self.omega
        self.file_on_cloud = {}

    def register_ES(self, EID):
        start = time.time()
        
        # generate lsk ∈ Z∗q and LPK for ES
        lskesi = self.group.random(ZR)
        LPKesi = self.g ** lskesi

        ESi = {
            'EID': EID,
            'lsk': lskesi,
            'LPK': LPKesi,
            'W': self.W,
            'Serv': self.Serv
        }

        end = time.time()
        rt = end - start

        return ESi, rt

    def register_SD(self, RIDi):
        start = time.time()
        
        # generate lsk ∈ Z∗q and LPK for SD
        lski = self.group.random(ZR)
        LPKi = self.g ** lski
        self.stored_LPKi = LPKi

        SDi = {
            'RID': RIDi,
            'lsk': lski,
            'LPK': LPKi,
            'omega': self.omega,
            'Serv': self.Serv
        }

        end = time.time()
        rt = end - start

        return SDi, rt
    
    # encrypt by ESa
    def encryption_function(self, m, ESa, EIDb, LPKesb):
        start = time.time()

        EIDa, lskesa, Serv = ESa['EID'], ESa['lsk'], ESa['Serv']

        # Step 1:
        heid_b = self.H2(EIDb)
        RSKa_b = LPKesb ** lskesa
        ra_b = self.H1(RSKa_b, Serv)
        SKa_b = heid_b ** ra_b
        yb = self.g ** ra_b

        # Step 2:
        k = self.group.random(ZR)
        symmetric_key = SymmetricCryptoAbstraction(self.H4(k))
        ED = symmetric_key.encrypt(m)
        
        # Step 3:
        index = self.group.random(ZR)  # Use random ZR
        self.file_on_cloud[str(index)] = ED  # Ensure index is a string
        hed = self.H4(ED)

        # Step 4:
        tesa = time.time()
        # tesa = self.group.random(ZR)
        r = self.H1(index, k, tesa, hed)
        C0 = self.g ** r

        # Step 5:
        hash_result = self.H3(pair(heid_b, yb) ** r)
        Cb_1_k = integer(int(k)) ^ hash_result
        Cb_1_index = integer(int(index)) ^ hash_result
        Cb_1_hed = bytes_to_integer_element(hed) ^ hash_result
        Cb_1_tesa = float_to_int_elem(tesa) ^ hash_result
        
        print('>>> PAIN START HERE (ENC) <<<')
        # print('k:      ', len(str(k)), k)
        # print('index:  ', len(str(index)), index)
        print('hed:    ', len(str(hed)), hed, type(hed))
        print('hed_int: ', bytes_to_integer_element(hed))
        # print('tesa:   ', len(str(tesa)), tesa)
        
        Cb_1 = Cb_1_k + Cb_1_index + Cb_1_hed + Cb_1_tesa
        Cb_2 = self.H2(C0, Cb_1) ** r

        # Step 6: 
        Hdr = {
            'C0': C0,
            'Cb_1_k': Cb_1_k,
            'Cb_1_index': Cb_1_index,
            'Cb_1_hed': Cb_1_hed,
            'Cb_1_tesa': Cb_1_tesa,
            'Cb_2': Cb_2
        }
        CT = {
            'Serv': Serv, 
            'EIDa': EIDa, 
            'Hdr': Hdr, 
            'tesa': tesa
        }

        # Step 7: 
        self.file_on_blockchain = CT

        end = time.time()
        rt = end - start

        return CT, rt


    # sign by SDi, send to ESb
    def sign_request_message(self, MServ, SDi, EIDa, LPKesb):
        start = time.time()

        lski, LPKi, omegai = SDi['lsk'], SDi['LPK'], SDi['omega']

        # 1. SDi generates the shared secret key SSKi
        SSKi = LPKesb ** lski

        # 2. SDi selects an anonymous secret key aski ∈ Z∗q and computes anonymous public key APKi
        aski = self.group.random(ZR)
        APKi = self.g ** aski

        # 3. SDi calculates temporary secret key TSKi and PIDi
        TSKi = LPKesb ** aski
        PIDi = LPKi + TSKi

        # 4. SDi chooses current timestamps ti and calculates thetai and signature σi
        ti = time.time()
        thetai = self.H1(self.W, ti, MServ, TSKi, SSKi, APKi, PIDi, EIDa)
        sigmai = aski + omegai * thetai

        # 5. SDi sends the message msgi to ESB
        msgi = {
            'MServ': MServ,
            'APKi': APKi,
            'PIDi': PIDi,
            'ti': ti,
            'sigmai': sigmai,
            'EIDa': EIDa
        }

        end = time.time()
        rt = end - start
        
        return msgi, rt

    # verify by ESb
    def verify_request_message(self, msgi, ESb):
        start = time.time()

        MServ, APKi, PIDi, ti, sigmai, EIDa = msgi['MServ'], msgi['APKi'], msgi['PIDi'], msgi['ti'], msgi['sigmai'], msgi['EIDa']
        lskesb = ESb['lsk']

        # 1. Check the freshness of the timestamp ti -> assume fresh enough
        if not is_timestamp_fresh(ti):
            print('Timestamp is not fresh. Discarding message.')
            end = time.time()
            rt = end - start
            return False, rt

        # Compute TSK'i = (APKi)^lskesb
        TSK_prime_i = APKi ** lskesb

        # 2. Compute LPKi = PIDi - TSK'i
        LPKi = PIDi - TSK_prime_i

        # Check if LPKi exists in the database
        if LPKi != self.stored_LPKi:
            print('LPKi does not exist in the database. Discarding message.')
            end = time.time()
            rt = end - start
            return False, rt

        # 3. Compute SSK'i = (LPKi)^lskesb
        SSK_prime_i = LPKi ** lskesb

        # 4. Query W based on MServ and calculate θ'i
        W = self.W # assume retrieved
        theta_prime_i = self.H1(W, ti, MServ, TSK_prime_i, SSK_prime_i, APKi, PIDi, EIDa)

        # 5. Verify if g^sigmai = APKi * W^theta_prime_i
        left_hand_side = self.g ** sigmai
        right_hand_side = APKi * (W ** theta_prime_i)

        end = time.time()
        rt = end - start

        if left_hand_side != right_hand_side:
            print('Verification failed. Discarding message.')
            return False, rt

        print('Verification succeeded. Message accepted.')
        return True, rt

    # transform by ESb
    def transform(self, CT, ESb, LPKesa, LPKi, APKi):
        start = time.time()

        # extract CT
        Serv, EIDa, Hdr, tesa = CT['Serv'], CT['EIDa'], CT['Hdr'], CT['tesa']
        C0 = Hdr['C0']
        Cb_1_k, Cb_1_index, Cb_1_hed, Cb_1_tesa = Hdr['Cb_1_k'], Hdr['Cb_1_index'], Hdr['Cb_1_hed'], Hdr['Cb_1_tesa']
        Cb_2 = Hdr['Cb_2']

        # extract ESb
        EIDb, lskesb = ESb['EID'], ESb['lsk']

        # 1. Compute RSK'a,b, r'a,b and SK'a,b
        RSK_prime_a_b = LPKesa ** lskesb
        r_prime_a_b = self.H1(RSK_prime_a_b, Serv)
        h_prime_eid_b = self.H2(EIDb)
        SK_prime_a_b = h_prime_eid_b ** r_prime_a_b

        # 2. Compute rb,i and SKb,i
        SSK_prime_i = LPKi ** lskesb
        rb_i = self.H1(SSK_prime_i, Serv)
        hi = self.H2(APKi)  
        SKb_i = hi ** rb_i

        # 3. Compute the transformation key T Kb→i
        tesb = time.time()
        T_Kb_to_i = SK_prime_a_b * (self.g ** self.H1(SKb_i, Serv, tesb))

        # 4. Compute transformed ciphertext components
        C_prime_0 = pair(self.g, C0)        # e(g, C0)
        C_prime_b_2 = pair(C0, T_Kb_to_i)   # e(C0, T_Kb→i)

        # 5. Generate the transformed ciphertext CTb→i
        CTb_to_i = {
            'C_prime_0': C_prime_0,
            'Cb_1_k': Cb_1_k,
            'Cb_1_index': Cb_1_index,
            'Cb_1_hed': Cb_1_hed,
            'Cb_1_tesa': Cb_1_tesa,
            'C_prime_b_2': C_prime_b_2
        }

        end = time.time()
        rt = end - start

        return CTb_to_i, tesb, rt
    
    # decrypt by SDi
    def decryption_function(self, CTb_to_i, tesb, SDi, LPKesb, APKi):
        start = time.time()

        C_prime_0, Cb_1_k, Cb_1_index, Cb_1_hed, Cb_1_tesa, C_prime_b_2 = CTb_to_i['C_prime_0'], CTb_to_i['Cb_1_k'], CTb_to_i['Cb_1_index'], CTb_to_i['Cb_1_hed'], CTb_to_i['Cb_1_tesa'], CTb_to_i['C_prime_b_2']
        lski, Serv = SDi['lsk'], SDi['Serv']

        SSKi = LPKesb ** lski

        # Step 1: Calculate h′i and r′b,i
        h_prime_i = self.H2(APKi)
        r_prime_b_i = self.H1(SSKi, Serv)
        SK_prime_b_i = h_prime_i ** r_prime_b_i

        # Step 2: Calculate (k||index||hed||tesa)
        hash_result = self.H3(C_prime_b_2 / (C_prime_0 ** self.H1(SK_prime_b_i, Serv, tesb)))
        k_output = hash_result ^ Cb_1_k
        index_output = hash_result ^ Cb_1_index
        hed_output = hash_result ^ Cb_1_hed
        tesa_output = hash_result ^ Cb_1_tesa

        k = self.group.init(ZR, int(k_output)) 
        index = self.group.init(ZR, int(index_output))
        hed = integer_element_to_bytes(hed_output)
        tesa = int_elem_to_float(int(tesa_output))

        # Step 3: Calculate the expected value
        ED = self.file_on_cloud.get(str(index))  # Ensure index is a string
        expected_C0_prime = pair(self.g, self.g) ** self.H1(index, k, tesa, hed)

        # print('########## DEC ##########')
        # print('ED:     ', ED)
        # print('CLOUD > ', self.file_on_cloud)

        if expected_C0_prime.__str__() == C_prime_0.__str__():
            print('equal')
        else:
            print('@@@@@@@@@@@@@ NOT EQUAL IDIOT @@@@@@@@@@@@@')
            print('expect_C0p: ', expected_C0_prime)
            print('C0p:        ', C_prime_0)
            print('>>> PAIN START HERE (DEC) <<<')
            # print('k:      ', len(str(k)), k)
            # print('index:  ', len(str(index)), index)
            print('hed:    ', len(str(hed)), hed, type(hed))
            print('hed_int: ', hed_output)
            # print('tesa:   ', len(str(tesa)), tesa)

            m = False
        
        symmetric_key = SymmetricCryptoAbstraction(self.H4(k))
        m_bytes = symmetric_key.decrypt(ED)
        m = m_bytes.decode('utf-8')
        print('m_out:  ', m, type(m))

        end = time.time()
        rt = end - start
        return m, rt

def integer_element_to_bytes(int_elem):
    # Convert integer.Element to a standard Python integer
    int_value = int(int_elem)
    
    # Calculate the length of bytes required to represent the integer
    byte_length = (int_value.bit_length() + 7) // 8
    
    # Convert the integer to bytes, ensure it is properly zero-padded
    return int_value.to_bytes(byte_length, byteorder='big', signed=False)

def bytes_to_integer_element(bytes_data):
    # Convert bytes to integer
    int_value = int.from_bytes(bytes_data, byteorder='big')
    
    return integer(int_value)

# Declare the scale factor once
scale_factor = 1e9  # Adjust the scale factor as needed for precision

def float_to_int_elem(value):
    # Convert a float to an integer element
    scaled_value = int(value * scale_factor)
    return integer(scaled_value)

def int_elem_to_float(int_elem):
    # Convert an integer element back to a float
    return int_elem / scale_factor

def is_timestamp_fresh(ti, threshold=1):
    """
    Check if the given timestamp `ti` is within the threshold time (in seconds) from the current time.

    Parameters:
    - ti (float): The timestamp to check.
    - threshold (int): The time threshold in seconds (default is 1 seconds).

    Returns:
    - bool: True if the timestamp is fresh, False otherwise.
    """
    current_time = time.time()  # Get the current timestamp
    return (current_time - ti) <= threshold  # Check if within the threshold

def generate_random_str(length):
    random_str = ''
    base_str = 'helloworlddfafj23i4jri3jirj23idaf2485644f5551jeri23jeri23ji23'
    for i in range(length):
        random_str += base_str[random.randint(0, length - 1)]
    return random_str


def main():
    groupObj = PairingGroup('SS512')
    n_array = np.arange(5, 30, 5)
    output_txt = './scheme4.txt'

    with open(output_txt, 'w+', encoding='utf-8') as f:
        f.write('{:3} {:18} {:18} {:18} {:18} {:18} {:18}\n'.format(
            'Seq', 'RegAveTime', 'EncAveTime', 'SignAveTime', 'VerifyAveTime', 'TransformAveTime', 'DecAveTime'
        ))

        for i in range(len(n_array)):
            scheme4 = MJ18(groupObj)
            seq = 5
            reg_tot, enc_tot, sgn_tot, vrf_tot, trf_tot, dec_tot = 0.0, 0.0, 0.0, 0.0, 0.0, 0.0

            for j in range(seq):
                n = n_array[i]
                print(f'\nn, seq {n} {j}')

                EIDa = generate_random_str(16)
                EIDb = generate_random_str(16)
                RIDi = generate_random_str(16)
                
                # 1. Register
                ESa, reg_time_ESa = scheme4.register_ES(EIDa)
                ESb, reg_time_ESb = scheme4.register_ES(EIDb)
                SDi, reg_time_SDi = scheme4.register_SD(RIDi)
                reg_tot += reg_time_ESa + reg_time_ESb + reg_time_SDi

                # Public keys
                LPKesb = ESb['LPK']  
                LPKesa = ESa['LPK']
                LPKi = SDi['LPK']

                # 2. Encryption
                m = generate_random_str(n)
                CT, enc_time = scheme4.encryption_function(m, ESa, EIDb, LPKesb)
                enc_tot += enc_time

                # 3. Sign message request
                MServ = generate_random_str(16)
                msgi, sgn_time = scheme4.sign_request_message(MServ, SDi, EIDa, LPKesb)
                sgn_tot += sgn_time
                APKi = msgi['APKi']

                # 4. Verify message request
                vrf_result, vrf_time = scheme4.verify_request_message(msgi, ESb)
                vrf_tot += vrf_time
                if not vrf_result:
                    print(f'Verification FAILED for n, seq: {n}, {j}')
                else:
                    print(f'Verification SUCCESS')

                # 5. Transformation
                CTb_to_i, tesb, trf_time = scheme4.transform(CT, ESb, LPKesa, LPKi, APKi)
                trf_tot += trf_time

                # 6. Decryption
                m_output, dec_time = scheme4.decryption_function(CTb_to_i, tesb, SDi, LPKesb, APKi)
                dec_tot += dec_time

                if not m_output:
                    print(f'Decryption ERROR (C`0 not equal) for n, seq: {n}, {j}')
                # else:
                #     print(f'Decryption SUCCESS 1')

                if m_output != m:
                    print(f'Decryption FAILED for n, seq: {n}, {j}')
                # else:
                #     print(f'Decryption SUCCESS 2')

                print('M_input:    ', m)
                print('M_output_1: ', m_output)

                total_tot = reg_tot + enc_tot + sgn_tot + vrf_tot + trf_tot + dec_tot
                print('total_tot:  ', total_tot)

            # Write the average times for the current n value
            avg_reg_time = reg_tot / seq
            avg_encryption_time = enc_tot / seq
            avg_sign_time = sgn_tot / seq
            avg_verification_time = vrf_tot / seq
            avg_transformation_time = trf_tot / seq
            avg_decryption_time = dec_tot / seq

            out0 = str(n_array[i]).zfill(2)
            out1 = str(format(avg_reg_time, '.16f'))
            out2 = str(format(avg_encryption_time, '.16f'))
            out3 = str(format(avg_sign_time, '.16f'))
            out4 = str(format(avg_verification_time, '.16f'))
            out5 = str(format(avg_transformation_time, '.16f'))
            out6 = str(format(avg_decryption_time, '.16f'))

            f.write(f'{out0}  {out1} {out2} {out3} {out4} {out5} {out6}\n')

if __name__ == '__main__':
    main()
