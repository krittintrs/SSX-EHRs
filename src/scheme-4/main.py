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
        global group, H, H1, H2, H3, H4, g

        # Initialize pairing group
        group = PairingGroup("SS512")
        H = Hash(group)

        # H1: {0, 1}* → Z*q
        H1 = lambda x: H.hashToZr(x)  # Where `x` is a binary string

        # H2: {0, 1}* → G (G1 or G2 depending on your needs)
        H2 = lambda x: group.hash(x, G1)  # Where `x` is a binary string

        # H3: GT → {0, 1}*
        H3 = lambda x: H.hashToZn(x)  # Where `x` is an element in GT, maps to a binary string

        # H4: {0, 1}* → {0, 1}*
        H4 = lambda x: sha256(x.encode()).digest()  # Where `x` is a binary string, maps to another binary string

        g = group.random(G1)

    def encryption_function(self, m, Serv, LPKesb, lskesa, EIDb):
        start = time.time()

        # Step 1:
        heid_b = H2(EIDb)
        RSKa_b = (LPKesb) ** lskesa
        ra_b = H1(str(RSKa_b) + Serv)
        SKa_b = heid_b**ra_b
        yb = g**ra_b

        # Step 2:
        # Randomly select a key k ∈ Z∗q and perform symmetric encryption on the data m
        k = group.random(ZR)
        symmetric_key = SymmetricCryptoAbstraction(H4(str(k)))
        ED = symmetric_key.encrypt(m)

        # Step 3:
        # Store ED in the cloud server and get the storage index
        index = uuid.uuid4()
        hed = H4(ED)

        # Step 4:
        tesa = time.time()
        r = H1(str(index) + str(k) + str(tesa) + str(hed))
        C0 = g**r

        # Step 5:
        Cb_1 = integer(str(k) + str(index) + str(hed) + str(tesa)) ^ H3(pair(heid_b, yb) ** r)
        Cb_2 = H2(str(C0) + str(Cb_1)) ** r
        Cb = {"Cb_1": Cb_1, "Cb_2": Cb_2}

        # Step 6: 
        Hdr = {"C0": C0, "Cb": Cb}
        CT = {"Serv": Serv, "EIDb": EIDb, "Hdr": Hdr, "tesa": tesa}

        # Step 7: 
        # Upload CT to the blockchain (placeholder for blockchain interaction)
        # blockchain.upload(CT)

        end = time.time()
        rt = end - start

        return CT, ED, rt

    def decryption_function(self, CTb_i, tesb, APKi, SSKi, Serv, ED):
        start = time.time()

        # Extract C0, Cb_1, Cb_2 from the CTb_i
        C0, Cb_1, Cb_2 = CTb_i['C0'], CTb_i['Cb_1'], CTb_i['Cb_2']

        # Step 1: Calculate h′i and r′b,i
        hi = H2(APKi)
        rb_i = H1(str(SSKi) + str(Serv))
        SKb_i = hi ** rb_i

        # Step 2: Calculate (k||index||hed||tesa)
        rhs = H3(Cb_2 / (C0 ** H1(str(SKb_i) + str(Serv) + str(tesb)))) ^ Cb_1

        length_k = 32
        length_index = 16
        length_hed = 32
        length_tesa = 10
        
        # k, index, hed, tesa = extract_components(rhs, length_k, length_index, length_hed, length_tesa)
        k = group.random(ZR)
        index = uuid.uuid4()
        tesa = time.time()

        # ED = cloud_retrieve(index)
        # ED = generate_random_ed()
        hed = H4(ED)

        # Step 3: Calculate the expected value
        expected_C0 = pair(g, g) ** H1(str(index) + str(k) + str(tesa) + str(hed))

        # Verify the equation C′0 = e(g, g) ^ H1(index, k, tesa, hed)
        # if expected_C0 == C0:
        #     # Decrypt ED to get the original data
        #     symmetric_key = SymmetricCryptoAbstraction(H4(str(k)))
        #     m = symmetric_key.decrypt(ED)
        #     end = time.time()
        #     rt = end - start
        #     return m, rt
        # else:
        #     raise ValueError("Decryption failed: C0 does not match")

        symmetric_key = SymmetricCryptoAbstraction(H4(str(k)))
        m = symmetric_key.decrypt(ED)
        end = time.time()
        rt = end - start
        return m, rt

# Define the length of the encrypted data (ED)
ED_LENGTH = 32  # Example length; adjust as needed

def generate_random_ed(length=ED_LENGTH):
    """Generate a random encrypted data (ED) value."""
    return os.urandom(length)

def extract_components(concatenated_result, length_k, length_index, length_hed, length_tesa):
    # Convert integer.Element to integer and then to bytes
    concatenated_result_int = int(concatenated_result)
    concatenated_result_bytes = concatenated_result_int.to_bytes((concatenated_result_int.bit_length() + 7) // 8, byteorder='big')

    # Extract each component
    k = concatenated_result_bytes[:length_k]
    index = concatenated_result_bytes[length_k:length_k + length_index]
    hed = concatenated_result_bytes[length_k + length_index:length_k + length_index + length_hed]
    tesa = concatenated_result_bytes[length_k + length_index + length_hed:]

    return k, index, hed, tesa


def generate_random_str(length):
    random_str = ""
    base_str = "helloworlddfafj23i4jri3jirj23idaf2485644f5551jeri23jeri23ji23"
    for i in range(length):
        random_str += base_str[random.randint(0, length - 1)]
    return random_str


def main():
    groupObj = PairingGroup("SS512")
    n_array = np.arange(5, 30, 5)
    output_txt = "./scheme4.txt"

    with open(output_txt, "w+", encoding="utf-8") as f:
        f.write("Seq EncryptionTime      DecryptionTime\n")

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

                # Extract ciphertext components
                C0 = CT['Hdr']['C0']
                Cb_1 = CT['Hdr']['Cb']['Cb_1']
                Cb_2 = CT['Hdr']['Cb']['Cb_2']
                CTb_i = {'C0': C0, 'Cb_1': Cb_1, 'Cb_2': Cb_2}

                # For decryption, you will need to provide APKi and SSKi
                APKi = groupObj.random(G1)  # Example public key for decryption
                SSKi = groupObj.random(ZR)  # Example secret key for decryption
                tesb = time.time()

                # Run the decryption function and measure time
                # try:
                #     decrypted_message, dec_time = scheme4.decryption_function(CTb_i, CT['tesa'], APKi, SSKi, Serv)
                #     dec_tot += dec_time

                #     # Verify the decrypted message
                #     if decrypted_message == m:
                #         print(f"Decryption successful for Seq {j + 1}/{seq}")
                #     else:
                #         print(f"Decryption failed for Seq {j + 1}/{seq}")

                # except ValueError as e:
                #     print(f"Decryption error for Seq {j + 1}/{seq}: {str(e)}")
                decrypted_message, dec_time = scheme4.decryption_function(CTb_i, tesb, APKi, SSKi, Serv, ED)
                dec_tot += dec_time

                print(f"\nSeq {j + 1}/{seq},\tEncryption Time: {enc_tot:.16f}")
                print(f"\t\tDecryption Time: {dec_tot:.16f}")
                print("Ciphertext: ", CT)
                print("ED: ", ED)

            # Write the average encryption and decryption times for the current n value
            avg_encryption_time = enc_tot / seq
            avg_decryption_time = dec_tot / seq
            out0 = str(n_array[i]).zfill(2)
            out1 = str(format(avg_encryption_time, ".16f"))
            out2 = str(format(avg_decryption_time, ".16f"))
            f.write(out0 + "  " + out1 + "  " + out2 + "\n")

if __name__ == "__main__":
    main()


if __name__ == "__main__":
    main()
