import time
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth

class MJ18(ABEncMultiAuth):
    def __init__(self, groupObj, degree, verbose=False):
        ABEncMultiAuth.__init__(self)
        self.group = groupObj
        self.d = degree

    def setup(self):
        start = time.time()
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

        end = time.time()
        rt = end - start

        return PK, VK, rt


    def prove(self, PK, VC):
        start = time.time()
        
        g_s_i, g_alpha_s_i = PK
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

        end = time.time()
        rt = end - start

        return pi, rt


    def verify(self, VK, pi):
        start = time.time()

        g_delta_p_s, g_delta_h_s, g_delta_alpha_p_s = pi
        g_alpha, g_t_s = VK

        pair_1 = pair(g_delta_alpha_p_s, self.g)
        pair_2 = pair(g_delta_p_s, g_alpha)
        pair_3 = pair(g_delta_p_s, self.g)
        pair_4 = pair(g_delta_h_s, g_t_s)
        
        is_valid_restriction = (pair_1 == pair_2)
        is_valid_cofactor    = (pair_3 == pair_4)

        # print(f"is_valid_restriction: {is_valid_restriction}")
        # print(f"is_valid_cofactor: {is_valid_cofactor}")

        end = time.time()
        rt = end - start

        return is_valid_restriction and is_valid_cofactor, rt

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

def test_zksnark(num_seqs=5):
    print("Starting zk-SNARK Test...")
    
    group = PairingGroup('SS512')
    d = 5
    
    # Open a file to write the results
    with open("zkp_auth.txt", "w") as file:
        file.write('{:18} {:18} {:18}\n'.format(
            'SetupAveTime', 'ProofAveTime', 'VerifyAveTime'
        ))
        
        total_setup_time, total_proof_time, total_verify_time = 0, 0, 0
            
        for i in range(num_seqs):
            zkp_auth = MJ18(group, d)

            VC = [group.random(ZR) for _ in range(d + 1)]

            PK, VK, setup_time = zkp_auth.setup()
            pi, proof_time = zkp_auth.prove(PK, VC)
            verified, verify_time = zkp_auth.verify(VK, pi)
            
            print(f"Verification result for seq {i}: {verified}")
            
            total_setup_time += setup_time   
            total_proof_time += proof_time   
            total_verify_time += verify_time   
            
        avg_setup_time = total_setup_time / num_seqs
        avg_proof_time = total_proof_time / num_seqs
        avg_verify_time = total_verify_time / num_seqs

        out1 = str(format(avg_setup_time, '.16f'))
        out2 = str(format(avg_proof_time, '.16f'))
        out3 = str(format(avg_verify_time, '.16f'))

        file.write(f'{out1} {out2} {out3}\n')

if __name__ == "__main__":
    test_zksnark()
