from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.core.math.integer import integer
group = PairingGroup('SS512')
# Encryption side
k = group.random(ZR)  # Create a pairing.Element
k_int = integer(int(k))  # Avoid the string conversion step

# Print and store values for debugging
print('Original k (pairing.Element):', k, 'Type:', type(k))
print('k_int (integer.Element):', k_int, 'Type:', type(k_int))

# Decryption side
print('k_int raw:', k_int)
actual_k = group.init(ZR, int(k_int))  # Convert back to pairing.Element
print('Recovered k:', actual_k)

# Print and compare values
print('Comparison:', k == actual_k)

from charm.core.math.integer import integer

# Original bytes object
original_bytes = b'o\xbcFM\xf3\n\xb6\xf9c\x8f\xc2\xac\x91p\xde/\x7f\xfdl\x0c\x1eit\xa1\x88?\xfd\xab`\xd0\xef\x82'

# Step 1: Convert bytes to int
int_value = int.from_bytes(original_bytes, byteorder='big')

# Step 2: Convert int to integer.Element
int_elem = integer(int_value)

# Step 3: Convert integer.Element back to int
recovered_int_value = int(int_elem)

# Step 4: Convert int back to bytes
byte_length = (recovered_int_value.bit_length() + 7) // 8
recovered_bytes = recovered_int_value.to_bytes(byte_length, byteorder='big')

# Print results
print("Original bytes:", original_bytes)
print("Integer value (from bytes):", int_value)
print("Integer.Element:", int_elem)
print("Recovered int value (from Integer.Element):", recovered_int_value)
print("Recovered bytes (from int):", recovered_bytes)
print("Conversion successful:", original_bytes == recovered_bytes)
