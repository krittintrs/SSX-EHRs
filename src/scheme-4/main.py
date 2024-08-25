from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.hash_module import Hash
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.secretutil import SecretUtil
from hashlib import sha256

# Initialize pairing group
group = PairingGroup('SS512')
H = Hash(group)

# H1: {0, 1}* → Z*q
H1 = lambda x: H.hashToZr(x)  # Where `x` is a binary string

# H2: {0, 1}* → G (G1 or G2 depending on your needs)
H2 = lambda x: H(x)  # Where `x` is a binary string, maps to G1 or G2

# H3: GT → {0, 1}*
H3 = lambda x: H.hashToZn(x)  # Where `x` is an element in GT, maps to a binary string

# H4: {0, 1}* → {0, 1}*
H4 = lambda x: sha256(x.encode()).digest()  # Where `x` is a binary string, maps to another binary string

# Example usage
binary_input = "example_input"
g1_element = H2(binary_input)  # H2: binary string -> G (G1/G2 element)
gt_element = pair(g1_element, g1_element)  # Pairing example to produce a GT element
hash_result_h3 = H3(gt_element)  # H3: GT -> binary string
hash_result_h4 = H4(binary_input)  # H4: binary string -> binary string



def encryption_function(m, Serv, EIDb, LPKesb, lsk_esa, cloud_server):
    # Step 1: 
    # Calculate h_eid,b = H2(EIDb)
    h_eidb = H2(EIDb)

    # Calculate RSKa,b = (LPKesb)^lsk_esa
    RSKab = LPKesb ** lsk_esa

    # Calculate r_a,b = H1(RSKab, Serv)
    r_ab = H1(str(RSKab) + Serv)

    # Calculate SKa,b = (heid,b)^r_a,b
    SKab = h_eidb ** r_ab

    # Calculate yb = g^r_a,b
    yb = group.random(G1) ** r_ab

    # Step 2: 
    # Randomly select a key k ∈ Z∗q and perform symmetric encryption on the data m
    k = group.random(ZR)
    symmetric_key = SymmetricCryptoAbstraction(H4(str(k)))
    ED = symmetric_key.encrypt(m)

    # Step 3: 
    # Store ED in the cloud server and get the storage index
    index = cloud_server.store(ED)

    # Calculate h_ed = H4(ED)
    h_ed = H4(ED)

    # Step 4: Select the current timestamp tesa
    t_esa = group.random(ZR)  # Assume t_esa is a random value in this context

    # Calculate r = H1(index, k, t_esa, h_ed)
    r = H1(str(index) + str(k) + str(t_esa) + h_ed)

    # Calculate C0 = g^r
    C0 = group.random(G1) ** r

    # Step 5: Compute Cb = (Cb,1, Cb,2)
    Cb_1 = (str(k) + str(index) + h_ed + str(t_esa)).encode() ^ H3(pair(h_eidb, yb) ** r)
    Cb_2 = H2(str(C0) + str(Cb_1)) ** r

    Cb = (Cb_1, Cb_2)

    # Step 6: Generate Hdr = (C0, Cb)
    Hdr = (C0, Cb)

    # Step 7: Set metadata CT = (Serv, EIDa, Hdr, t_esa)
    CT = (Serv, EIDb, Hdr, t_esa)

    return CT
