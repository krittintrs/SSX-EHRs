import numpy as np

def polynomials_equal(p_coeffs, expected_coeffs):
    """
    Check if two polynomials are equal by comparing their coefficients.
    """
    return np.allclose(p_coeffs, expected_coeffs)

def main():
    # Define polynomials p(x) and t(x)
    p_coeffs = [2, -6, 2, 2]  # Example coefficients for p(x)
    t_coeffs = [1, -1]        # Example coefficients for t(x)

    # Perform polynomial division to find h(x)
    quotient, remainder = np.polydiv(p_coeffs, t_coeffs)

    # Display results
    print("Quotient (h(x) coefficients):", quotient)
    print("Remainder:", remainder)

    # Reconstruct p(x) from h(x) and t(x)
    p_reconstructed = np.polyadd(np.polymul(quotient, t_coeffs), remainder)

    print(p_reconstructed)
    # Check if reconstructed p(x) matches the original p(x)
    if polynomials_equal(p_coeffs, p_reconstructed):
        print("p(x) = h(x) * t(x) check passed.")
    else:
        print("p(x) = h(x) * t(x) check failed.")

if __name__ == "__main__":
    main()
