import numpy as np
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.core.math.integer import integer

class MJ18(ABEncMultiAuth):
    def __init__(self, groupObj, degree, verbose=False):
        ABEncMultiAuth.__init__(self)
        self.group = groupObj
        self.d = degree

    def setup(self):
        self.s = self.group.random(ZR)
        self.alpha = self.group.random(ZR)
        self.g = self.group.random(G1)
        
        g_alpha = self.g ** self.alpha
        g_s_i = [self.g ** (self.s ** i) for i in range(self.d + 1)]
        g_alpha_s_i = [self.g ** (self.alpha * (self.s ** i)) for i in range(self.d + 1)]

        self.t_coeffs = [self.group.random(ZR) for _ in range(1)]

        t_s = sum(self.t_coeffs[i] * (self.s ** i) for i in range(len(self.t_coeffs)))
        gt_s = self.g ** t_s

        PK = (g_s_i, g_alpha_s_i)
        VK = (g_alpha, gt_s)
        return PK, VK


    def prove(self, PK, VC):
        g_s_i, g_alpha_s_i = PK

        # Define p(x) as VC
        p_coeffs = VC

        # Compute g^p(s)
        gp_s = self.group.init(G1, 1)
        for i in range(len(p_coeffs)):
            gp_s *= g_s_i[i] ** p_coeffs[i]

        # Perform polynomial division
        h_coeffs, _ = polynomial_division(p_coeffs, self.t_coeffs, self.group)

        # Compute g^h(s) with h_coeffs
        gh_s = self.group.init(G1, 1)
        for i in range(len(h_coeffs)):
            gh_s *= g_s_i[i] ** h_coeffs[i]
        
        # Compute g^alphap(s)
        g_alpha_p_s = self.group.init(G1, 1)
        for i in range(self.d + 1):
            g_alpha_p_s *= g_alpha_s_i[i] ** p_coeffs[i]

        delta = self.group.random(ZR)
        pi = (gp_s ** delta, gh_s ** delta, g_alpha_p_s ** delta)

        return pi


    def verify(self, VK, pi):
        g_delta_p_s, g_delta_h_s, g_delta_alpha_p_s = pi
        g_alpha, g_t_s = VK

        pair_1 = pair(g_delta_alpha_p_s, self.g)
        pair_2 = pair(g_delta_p_s, g_alpha)
        pair_3 = pair(g_delta_p_s, self.g)
        pair_4 = pair(g_delta_h_s, g_t_s)
        
        is_valid_restriction = (pair_1 == pair_2)
        is_valid_cofactor    = (pair_3 == pair_4)

        print(f"is_valid_restriction: {is_valid_restriction}")
        print(f"is_valid_cofactor: {is_valid_cofactor}")

        return is_valid_restriction and is_valid_cofactor

def polynomial_multiply(a, b, group):
    # Initialize result polynomial with zeros
    result_degree = len(a) + len(b) - 2
    result = [group.init(ZR, 0) for _ in range(result_degree + 1)]
    
    # Multiply polynomials a and b
    for i in range(len(a)):
        for j in range(len(b)):
            result[i + j] += a[i] * b[j]
    
    return result

def polynomial_division(p, t, group):
    # Initialize zero element
    zero = group.init(ZR, 0)

    # Ensure t(x) is not zero
    if len(t) == 0 or all(coef == zero for coef in t):
        raise ValueError("Denominator polynomial cannot be zero")

    # Initialize the quotient and remainder
    quotient = [zero for _ in range(len(p) - len(t) + 1)]
    remainder = p.copy()

    # Polynomial long division
    for i in range(len(p) - len(t) + 1):
        if remainder[i] == zero:
            continue
        coef = remainder[i] / t[0]
        quotient[i] = coef
        for j in range(len(t)):
            remainder[i + j] -= coef * t[j]

    # Trim leading zeros from remainder
    while remainder and remainder[-1] == zero:
        remainder.pop()

    return quotient, remainder

def verify_polynomial_division(p, t, quotient, remainder, group):
    # Multiply quotient and t(x)
    product = polynomial_multiply(quotient, t, group)

    # Add remainder to the product
    for i in range(len(remainder)):
        if i < len(product):
            product[i] += remainder[i]
        else:
            product.append(remainder[i])

    # Check if product matches p(x)
    return len(p) == len(product) and all(p[i] == product[i] for i in range(len(p)))

def test_zksnark():
    print("Starting zk-SNARK Test...")
    
    group = PairingGroup('SS512')
    d = 3

    authToken = MJ18(group, d)

    # VC = [group.random(ZR) for _ in range(d + 1)]
    VC = [group.random(ZR) for _ in range(d + 1)]

    PK, VK = authToken.setup()
    pi = authToken.prove(PK, VC)
    verified = authToken.verify(VK, pi)
    
    print(f"Verification result: {verified}")

test_zksnark()
