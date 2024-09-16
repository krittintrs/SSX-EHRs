'''
John Bethencourt, Brent Waters (Pairing-based)
 
| From: "Ciphertext-Policy Attribute-Based Encryption".
| Published in: 2007
| Available from: 
| Notes: 
| Security Assumption: 
|
| type:           ciphertext-policy attribute-based encryption (public key)
| setting:        Pairing

:Authors:    J Ayo Akinyele
:Date:            04/2011
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output

# type annotations
pk_t = { 'g':G1, 'g2':G2, 'h':G1, 'f':G1, 'e_gg_alpha':GT }
mk_t = {'beta':ZR, 'g2_alpha':G2 }
sk_t = { 'D':G2, 'Dj':G2, 'Djp':G1, 'S':str }
ct_t = { 'C_tilde':GT, 'C':G1, 'Cy':G1, 'Cyp':G2 }

debug = False
class CPabe_BSW07(ABEnc):
    """
    >>> from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
    >>> group = PairingGroup('SS512')
    >>> cpabe = CPabe_BSW07(group)
    >>> msg = group.random(GT)
    >>> attributes = ['ONE', 'TWO', 'THREE']
    >>> access_policy = '((four or three) and (three or one))'
    >>> (master_public_key, master_key) = cpabe.setup()
    >>> secret_key = cpabe.keygen(master_public_key, master_key, attributes)
    >>> cipher_text = cpabe.encrypt(master_public_key, msg, access_policy)
    >>> decrypted_msg = cpabe.decrypt(master_public_key, secret_key, cipher_text)
    >>> msg == decrypted_msg
    True
    """ 
         
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj

    @Output(pk_t, mk_t)    
    def setup(self):
        g, gp = group.random(G1), group.random(G2)
        alpha, beta = group.random(ZR), group.random(ZR)
        # initialize pre-processing for generators
        g.initPP(); gp.initPP()
        
        h = g ** beta; f = g ** ~beta
        e_gg_alpha = pair(g, gp ** alpha)
        
        pk = { 'g':g, 'g2':gp, 'h':h, 'f':f, 'e_gg_alpha':e_gg_alpha }
        mk = {'beta':beta, 'g2_alpha':gp ** alpha }
        return (pk, mk)
    
    @Input(pk_t, mk_t, [str])
    @Output(sk_t)
    def keygen(self, pk, mk, S):
        r = group.random() 
        g_r = (pk['g2'] ** r)    
        D = (mk['g2_alpha'] * g_r) ** (1 / mk['beta'])        
        D_j, D_j_pr = {}, {}
        for j in S:
            r_j = group.random()
            D_j[j] = g_r * (group.hash(j, G2) ** r_j)
            D_j_pr[j] = pk['g'] ** r_j
        return { 'D':D, 'Dj':D_j, 'Djp':D_j_pr, 'S':S }
    
    @Input(pk_t, GT, str)
    @Output(ct_t)
    def encrypt(self, pk, M, policy_str): 
        policy = util.createPolicy(policy_str)
        a_list = util.getAttributeList(policy)
        s = group.random(ZR)
        shares = util.calculateSharesDict(s, policy)      

        C = pk['h'] ** s
        C_y, C_y_pr = {}, {}
        for i in shares.keys():
            j = util.strip_index(i)
            C_y[i] = pk['g'] ** shares[i]
            C_y_pr[i] = group.hash(j, G2) ** shares[i] 
        
        return { 'C_tilde':(pk['e_gg_alpha'] ** s) * M,
                 'C':C, 'Cy':C_y, 'Cyp':C_y_pr, 'policy':policy_str, 'attributes':a_list }
    
    @Input(pk_t, sk_t, ct_t)
    @Output(GT)
    def decrypt(self, pk, sk, ct):
        policy = util.createPolicy(ct['policy'])
        pruned_list = util.prune(policy, sk['S'])
        if pruned_list == False:
            return False
        z = util.getCoefficients(policy)
        A = 1 
        for i in pruned_list:
            j = i.getAttributeAndIndex(); k = i.getAttribute()
            A *= ( pair(ct['Cy'][j], sk['Dj'][k]) / pair(sk['Djp'][k], ct['Cyp'][j]) ) ** z[j]
        
        return ct['C_tilde'] / (pair(ct['C'], sk['D']) / A)

import os
import hashlib
from charm.toolbox.pairinggroup import PairingGroup

# Function to hash bytes to generate an AES key
def hash_to_aes_key(data, key_length=16):
    hash_bytes = hashlib.sha256(data).digest()  # Hash the input data
    aes_key = hash_bytes[:key_length]  # Truncate or adjust to the desired AES key length
    return aes_key

def aes_key_to_gt(group, aes_key):
    aes_key_hash_int = int.from_bytes(aes_key, byteorder='big')  # Convert hash to integer
    aes_key_gt = group.init(GT, aes_key_hash_int)  # Initialize GT element from integer
    return aes_key_gt

def gt_to_aes_key(group, aes_key_gt):
    # Serialize the GT element to bytes
    print('GT: >>> ', aes_key_gt)
    aes_key_bytes = group.serialize(aes_key_gt)
    print("Serialized GT bytes:", aes_key_bytes)
    
    # Hash the serialized bytes to derive the AES key
    aes_key_hash = hashlib.sha256(aes_key_bytes).digest()
    print("SHA256 Hash:", aes_key_hash)
    
    # Truncate or adjust to 16 bytes for AES-128
    aes_key = aes_key_hash[:16]
    
    return aes_key

def main():
    group = PairingGroup('SS512')

    # Step 1: Generate a random AES key
    raw_key = os.urandom(32)  # Raw data to hash for the AES key
    aes_key = hash_to_aes_key(raw_key)  # Convert raw data to AES key
    print("Original AES Key:", aes_key)

    # Step 2: Encrypt the AES key using CP-ABE
    cpabe = CPabe_BSW07(group)
    attrs = ['ONE', 'TWO', 'THREE']
    access_policy = '((four or three) and (three or one))'
    (pk, mk) = cpabe.setup()
    sk = cpabe.keygen(pk, mk, attrs)

    aes_key_gt = aes_key_to_gt(group, aes_key)
    print("AES Key as GT Element:", aes_key_gt)

    ct = cpabe.encrypt(pk, aes_key_gt, access_policy)
    print("Ciphertext (CT):", ct)

    # Step 3: Decrypt the AES key using CP-ABE
    rec_msg = cpabe.decrypt(pk, sk, ct)
    print("Decrypted Ciphertext (rec_msg):", rec_msg)
    
    # Step 4: Convert the GT element back to the AES key
    decrypted_aes_key = gt_to_aes_key(group, rec_msg)
    print("Decrypted AES Key:", decrypted_aes_key)

    # Ensure the decrypted AES key matches the original AES key
    print("Original AES Key Length:", (aes_key))
    print("Decrypted AES Key Length:", (decrypted_aes_key))
    
    if aes_key == decrypted_aes_key:
        print("AES key successfully decrypted and matches the original key!")
    else:
        print("Decryption failed: AES keys do not match!")

if __name__ == "__main__":
    main()
