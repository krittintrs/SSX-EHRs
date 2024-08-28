import os
import random
import time
import numpy as np
import uuid
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
        self.H2 = lambda *args: self.group.hash(''.join([str(arg) for arg in args]), G1)  # Maps to G1 (or G2 if needed)

        # H3: GT → {0, 1}*
        self.H3 = lambda *args: self.H.hashToZn(''.join([str(arg) for arg in args]))  # Maps GT to {0, 1}
        
        # H4: {0, 1}* → {0, 1}*
        self.H4 = lambda *args: sha256(''.join([str(arg) for arg in args]).encode()).digest()  # Maps {0, 1}* to {0, 1}*

        self.g = self.group.random(G1)
        self.s = self.group.random(ZR)
        self.Tc = time.time()
        self.Serv = 'IIoT service X'
        self.omega = self.H1(self.Serv, self.s, self.Tc)
        self.W = self.g ** self.omega

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
    
    def encryption_function(self, m, ESa, ESb):
        start = time.time()

        EIDa, lskesa = ESa['EID'], ESa['lsk']
        EIDb, LPKesb, Serv = ESb['EID'], ESb['LPK'], ESb['Serv']

        # Step 1:
        heid_b = self.H2(EIDb)
        RSKa_b = LPKesb ** lskesa
        ra_b = self.H1(RSKa_b, Serv)
        SKa_b = heid_b ** ra_b
        yb = self.g ** ra_b

        # Step 2:
        # Randomly select a key k ∈ Z∗q and perform symmetric encryption on the data m
        k = self.group.random(ZR)
        symmetric_key = SymmetricCryptoAbstraction(self.H4(k))
        ED = symmetric_key.encrypt(m)

        # Step 3:
        index = uuid.uuid4()
        self.file_on_cloud = {'index': index, 'ED': ED}
        hed = self.H4(ED)

        # Step 4:
        tesa = time.time()
        r = self.H1(index, k, tesa, hed)
        C0 = self.g ** r

        # Step 5:
        Cb_1_k = integer(str(k)) ^ self.H3(pair(heid_b, yb) ** r)
        Cb_1_index = integer(str(index)) ^ self.H3(pair(heid_b, yb) ** r)
        Cb_1_hed = integer(str(hed)) ^ self.H3(pair(heid_b, yb) ** r)
        Cb_1_tesa = integer(str(tesa)) ^ self.H3(pair(heid_b, yb) ** r)
        
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
        # Upload CT to the blockchain (placeholder for blockchain interaction)
        self.file_on_blockchain = CT

        end = time.time()
        rt = end - start

        return CT, ED, rt

    def sign_request_message(self, MServ, ESa, ESb, SDi):
        start = time.time()

        EIDa = ESa['EID']
        LPKesb, W = ESb['LPK'], ESb['W']
        lski, LPKi = SDi['lsk'], SDi['LPK']

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
        thetai = self.H1(W, ti, MServ, TSKi, SSKi, APKi, PIDi, EIDa)
        w = self.group.random(ZR)  # w could be some global or predefined value
        sigmai = aski + w * thetai

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

    def verify_message(self, msgi, ESb):
        start = time.time()

        MServ, APKi, PIDi, ti, sigmai, EIDa = msgi['MServ'], msgi['APKi'], msgi['PIDi'], msgi['ti'], msgi['sigmai'], msgi['EIDa']
        lskesb = ESb['lsk']

        # 1. Check the freshness of the timestamp ti -> assume fresh enough

        # Compute TSK'i = (APKi)^lskesb
        TSK_prime_i = APKi ** lskesb

        # 2. Compute LPKi = PIDi - TSK'i
        LPKi = PIDi - TSK_prime_i

        # Check if LPKi exists in the database
        # if LPKi not in database:
        #     print('LPKi does not exist in the database. Discarding message.')
        #     return False

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

    def transform(self, CT, ESa, ESb, SDi, msgi):
        start = time.time()

        Serv, EIDa, Hdr, tesa = CT['Serv'], CT['EIDa'], CT['Hdr'], CT['tesa']
        C0 = Hdr['C0']
        Cb_1_k, Cb_1_index, Cb_1_hed, Cb_1_tesa = Hdr['Cb_1_k'], Hdr['Cb_1_index'], Hdr['Cb_1_hed'], Hdr['Cb_1_tesa']
        Cb_2 = Hdr['Cb_2']

        LPKesa = ESa['LPK']
        EIDb, lskesb = ESb['EID'], ESb['lskesb']
        LPKi = SDi['LPK']
        APKi = msgi['APKi']

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
    
    def decryption_function(self, CTb_to_i, tesb, ESb, SDi, msgi):
        start = time.time()

        C_prime_0, Cb_1_k, Cb_1_index, Cb_1_hed, Cb_1_tesa, C_prime_b_2 = CTb_to_i['C_prime_0'], CTb_to_i['Cb_1_k'], CTb_to_i['Cb_1_index'], CTb_to_i['Cb_1_hed'], CTb_to_i['Cb_1_tesa'], CTb_to_i['C_prime_b_2']
        LPKesb, Serv = ESb['LPK'], ESb['Serv']
        lski = SDi['lsk']
        APKi = msgi['APKi']

        SSKi = LPKesb ** lski

        # Step 1: Calculate h′i and r′b,i
        h_prime_i = self.H2(APKi)
        r_prime_b_i = self.H1(SSKi, Serv)
        SK_prime_b_i = h_prime_i ** r_prime_b_i

        # Step 2: Calculate (k||index||hed||tesa)
        hash_rhs = self.H3(C_prime_b_2 / (C_prime_0 ** self.H1(SK_prime_b_i, Serv, tesb)))
        k = hash_rhs ^ Cb_1_k
        index = hash_rhs ^ Cb_1_index
        hed = hash_rhs ^ Cb_1_hed
        tesa = hash_rhs ^ Cb_1_tesa

        # Step 3: Calculate the expected value
        ED = self.file_on_cloud[index]
        expected_C0_prime = pair(self.g, self.g) ** self.H1(index, k, tesa, hed)

        if expected_C0_prime.__str__() == C_prime_0.__str__():
            print('equal')
            symmetric_key = SymmetricCryptoAbstraction(self.H4(k))
            m = symmetric_key.decrypt(ED)
            end = time.time()
            rt = end - start
            return m, rt
        else:
            print('not equal')
            return False, rt

# Define the length of the encrypted data (ED)
ED_LENGTH = 32  # Example length; adjust as needed

def generate_random_ed(length=ED_LENGTH):
    '''Generate a random encrypted data (ED) value.'''
    return os.urandom(length)

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
        f.write('Seq EncryptionTime      DecryptionTime\n')

        for i in range(len(n_array)):
            scheme4 = MJ18(groupObj)
            seq = 5
            enc_tot = 0.0
            dec_tot = 0.0

            for j in range(seq):
                n = n_array[i]
                m = generate_random_str(n)
                Serv = generate_random_str(n)
                LPKesb = groupObj.random(G1)  # Example public key
                lskesa = groupObj.random(ZR)  # Example secret key
                EIDb = generate_random_str(n)

                # Run the encryption function and measure time
                CT, ED, enc_time = scheme4.encryption_function(m, Serv, LPKesb, lskesa, EIDb)
                enc_tot += enc_time

                # Extract ciphertext components for decryption
                CTb_i = {
                    'C0': CT['Hdr']['C0'],
                    'Cb_1_k': CT['Hdr']['Cb']['Cb_1_k'],
                    'Cb_1_index': CT['Hdr']['Cb']['Cb_1_index'],
                    'Cb_1_hed': CT['Hdr']['Cb']['Cb_1_hed'],
                    'Cb_1_tesa': CT['Hdr']['Cb']['Cb_1_tesa'],
                    'Cb_2': CT['Hdr']['Cb']['Cb_2']
                }

                # For decryption, provide APKi and SSKi
                APKi = groupObj.random(G1)  # Example public key for decryption
                SSKi = groupObj.random(ZR)  # Example secret key for decryption
                tesb = CT['tesa']  # Use the same timestamp from encryption

                # Run the decryption function and measure time
                # try:
                #     decrypted_message, dec_time = scheme4.decryption_function(CTb_i, tesb, APKi, SSKi, Serv, ED)
                #     dec_tot += dec_time

                #     # Verify the decrypted message
                #     if decrypted_message == m:
                #         print(f'Decryption successful for Seq {j + 1}/{seq}')
                #     else:
                #         print(f'Decryption failed for Seq {j + 1}/{seq}')

                # except ValueError as e:
                #     print(f'Decryption error for Seq {j + 1}/{seq}: {str(e)}')
                
                decrypted_message, dec_time = scheme4.decryption_function(CTb_i, tesb, APKi, SSKi, Serv, ED)
                dec_tot += dec_time

                print(f'\nSeq {j + 1}/{seq},\tEncryption Time: {enc_tot:.16f}')
                print(f'\t\tDecryption Time: {dec_tot:.16f}')
                # print('Ciphertext: ', CT)
                # print('ED: ', ED)

            # Write the average encryption and decryption times for the current n value
            avg_encryption_time = enc_tot / seq
            avg_decryption_time = dec_tot / seq
            out0 = str(n_array[i]).zfill(2)
            out1 = str(format(avg_encryption_time, '.16f'))
            out2 = str(format(avg_decryption_time, '.16f'))
            f.write(out0 + '  ' + out1 + '  ' + out2 + '\n')

if __name__ == '__main__':
    main()

if __name__ == '__main__':
    main()


if __name__ == '__main__':
    main()
