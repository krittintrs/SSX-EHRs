from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth

class MJ18(ABEncMultiAuth):
    def __init__(self, groupObj, degree, verbose=False):
        ABEncMultiAuth.__init__(self)
        self.group = groupObj
        self.d = degree

    # Setup Phase
    def setup(self):
        self.s = self.group.random(ZR)
        self.alpha = self.group.random(ZR)
        self.g = self.group.random(G1)
        
        g_alpha = self.g ** self.alpha
        g_s_i = [self.g ** (self.s ** i) for i in range(self.d + 1)]  # {g^(s^i)}
        g_alpha_s_i = [self.g ** (self.alpha * (self.s ** i)) for i in range(self.d + 1)]  # {g^(alpha*s^i)}
        
        # Proving key (PK) and verification key (VK)
        PK = (g_s_i, g_alpha_s_i)
        VK = (g_alpha, self.g ** (self.s ** self.d))  # (g^alpha, g^t(s))
        return PK, VK

    # Proving Phase
    def prove(self, PK, VC):
        g_s_i, g_alpha_s_i = PK
    
        # Parse VC into a polynomial p(x)
        coeffs = [VC[i] for i in range(self.d + 1)]  # VC is encoded into polynomial coefficients

        # Compute g^p(s) = prod((g^(s^i))^c_i)
        gp_s = self.group.init(G1, 1)  # Initialize as 1
        for i in range(self.d + 1):
            gp_s *= g_s_i[i] ** coeffs[i]

        # Now compute g^h(s)
        # Divide p(x) by t(x) = s^d to get h(x), i.e., shift the coefficients
        h_coeffs = [coeffs[i] for i in range(self.d)]  # h(x) has degree d-1, so we exclude the highest degree term
        gh_s = self.group.init(G1, 1)  # Initialize g^h(s) as 1
        for i in range(len(h_coeffs)):
            gh_s *= g_s_i[i] ** h_coeffs[i]
        
        # Compute g_alpha_p(s)
        g_alpha_p_s = self.group.init(G1, 1)
        for i in range(self.d + 1):
            g_alpha_p_s *= g_alpha_s_i[i] ** coeffs[i]
        
        # Random scalar delta
        delta = self.group.random(ZR)
        
        # Randomized proof
        pi = (gp_s ** delta, gh_s ** delta, g_alpha_p_s ** delta)
        
        return pi


    # Verification Phase
    def verify(self, VK, pi):
        # Unpack proof components
        g_delta_p_s, g_delta_h_s, g_delta_alpha_p_s = pi

        # Unpack verification key components
        g_alpha, g_t_s = VK
        
        print(f"g_delta_p_s: {g_delta_p_s}")
        print(f"g_delta_h_s: {g_delta_h_s}")
        print(f"g_delta_alpha_p_s: {g_delta_alpha_p_s}")
        print(f"g_alpha: {g_alpha}")
        print(f"g_t_s: {g_t_s}")

        # Compute pairings
        pair_1 = pair(g_delta_alpha_p_s, self.g)
        pair_2 = pair(g_delta_p_s, g_alpha)
        pair_3 = pair(g_delta_h_s, g_t_s)
        
        # Print intermediate values for debugging
        print(f"pair_1: {pair_1}")
        print(f"pair_2: {pair_2}")
        print(f"pair_3: {pair_3}")
        
        # Validate proof
        is_valid_restriction = (pair_1 == pair_2)
        is_valid_cofactor    = (pair_1 == pair_3)

        # Print validity results
        print(f"is_valid_restriction: {is_valid_restriction}")
        print(f"is_valid_cofactor: {is_valid_cofactor}")

        # Return overall validity
        return is_valid_restriction and is_valid_cofactor


# Test Code
def test_zksnark():
    print("Starting zk-SNARK Test...")
    
    # Initialize pairing group
    group = PairingGroup('SS512')
    d = 3

    authToken = MJ18(group, d)

    VC = [group.random(ZR) for _ in range(d + 1)]

    PK, VK = authToken.setup()
    pi = authToken.prove(PK, VC)
    verified = authToken.verify(VK, pi)
    
    print(f"Verification result: {verified}")

# Run test
test_zksnark()
