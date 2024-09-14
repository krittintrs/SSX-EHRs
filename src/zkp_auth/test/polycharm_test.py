from charm.toolbox.pairinggroup import PairingGroup, ZR

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

# Example usage
group = PairingGroup('BN254')  # or another group

# Define polynomials as lists of coefficients
p = [group.random(ZR) for _ in range(3)]  # p(x) = a0 + a1*x + a2*x^2 + a3*x^3
t = [group.init(ZR, 1)]  # t(x) = b0 + b1*x + b2*x^2

# Perform polynomial division
quotient, remainder = polynomial_division(p, t, group)

# Verify the result
is_correct = verify_polynomial_division(p, t, quotient, remainder, group)

print("Polynomial p(x):", p)
print("Polynomial t(x):", t)
print("Quotient h(x):", quotient)
print("Remainder:", remainder)
print("Verification result:", is_correct)
