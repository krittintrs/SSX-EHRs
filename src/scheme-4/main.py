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

        # Example usage
        # binary_input = "example_input"
        # g1_element = H2(binary_input)  # H2: binary string -> G (G1/G2 element)
        # gt_element = pair(g1_element, g1_element)  # Pairing example to produce a GT element
        # hash_result_h3 = H3(gt_element)  # H3: GT -> binary string
        # hash_result_h4 = H4(binary_input)  # H4: binary string -> binary string

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

        return CT, rt


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
        f.write("Seq EncryptionTime\n")

        for i in range(len(n_array)):
            mj18 = MJ18(groupObj)
            seq = 5
            enc_tot = 0.0

            for j in range(seq):
                n = n_array[i]
                m = generate_random_str(n)
                Serv = generate_random_str(n)
                LPKesb = groupObj.random(G1)  # Example public key
                lskesa = groupObj.random(ZR)  # Example secret key
                EIDb = generate_random_str(n)

                # Run the encryption function and measure time
                CT, enc_time = mj18.encryption_function(m, Serv, LPKesb, lskesa, EIDb)

                enc_tot += enc_time

                # Validity check (example, replace with actual checks)
                print(f"\nSeq {j + 1}/{seq}, Encryption Time: {enc_tot:.16f}")
                print("Ciphertext: ", CT)

            # Write the average encryption time for the current n value
            avg_encryption_time = enc_tot / seq
            out0 = str(n_array[i]).zfill(2)
            out1 = str(format(avg_encryption_time, ".16f"))
            f.write(out0 + "  " + out1 + "\n")


if __name__ == "__main__":
    main()
