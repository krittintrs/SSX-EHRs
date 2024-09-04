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
from charm.core.math.integer import integer

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


def main():   
    groupObj = PairingGroup('SS512')

    cpabe = CPabe_BSW07(groupObj)
    attrs = ['ONE', 'TWO', 'THREE']
    access_policy = '((four or three) and (three or one))'
    if debug:
        print("Attributes =>", attrs); print("Policy =>", access_policy)

    (pk, mk) = cpabe.setup()
    
    sk = cpabe.keygen(pk, mk, attrs)
    print("sk :=>", sk)

    input_file_dir = '../sample/input/'
    input_file = f'{input_file_dir}input_file_50000.bin'
    with open(input_file, 'rb') as f_in:
        file = f_in.read()

    # print(type(rand_msg))
    # from hashlib import sha256
    # rand_msg = sha256(rand_msg)
    # print(type(rand_msg))
    # x = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09'
    # # rand_msg = pair(int(x), GT)
    # rand_msg = groupObj.random(GT)

    from charm.core.engine.util import objectToBytes, bytesToObject
    
    x = b'\x00\x01\x02\x03\x04\x05\x06\x07'
    rand_msg = group.serialize(x)

    if debug: print("msg =>", rand_msg)
    ct = cpabe.encrypt(pk, rand_msg, access_policy)
    if debug: print("\n\nCiphertext...\n")
    groupObj.debug(ct)

    rec_msg = cpabe.decrypt(pk, sk, ct)
    if debug: print("\n\nDecrypt...\n")
    if debug: print("Rec msg =>", rec_msg)

    assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
    if debug: print("Successful Decryption!!!")

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

if __name__ == "__main__":
    debug = True
    main()