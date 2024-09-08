# ------------- TEST interger to pairing -------------
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

# ------------- TEST interger to time -------------
import time
from charm.core.math.integer import integer

def float_to_integer_element(timestamp):
    # Convert the float timestamp to an integer
    # Choose a high precision scaling factor to retain accuracy
    scale_factor = 1e9  # Use a higher precision scaling factor
    return integer(int(timestamp * scale_factor))

def integer_element_to_float(int_elem):
    # Convert integer.Element back to float
    scale_factor = 1e9  # Use the same scaling factor as before
    return float(int(int_elem)) / scale_factor

# Original timestamp
timestamp = time.time()
print("Original timestamp:", timestamp)

# Convert timestamp to integer.Element
int_elem = float_to_integer_element(timestamp)
print("Integer.Element:", int_elem)

# Convert integer.Element back to timestamp
recovered_timestamp = integer_element_to_float(int_elem)
print("Recovered timestamp:", recovered_timestamp)

# Exact equality check
is_equal = timestamp == recovered_timestamp
print("Equal:", is_equal)

# ------------- TEST interger to bytes -------------
from charm.core.math.integer import integer

def bytes_to_integer_element(byte_data):
    # Convert bytes to an integer
    int_value = int.from_bytes(byte_data, byteorder='big', signed=False)
    # Convert integer to integer.Element
    return integer(int_value)

def integer_element_to_bytes(int_elem, original_length):
    # Convert integer.Element to a standard Python integer
    int_value = int(int_elem)
    
    # Convert the integer to bytes
    return int_value.to_bytes(original_length, byteorder='big', signed=False)

def test_conversion():
    # Original byte data (you can modify this to test different cases)
    original_bytes = b'\x00\xbb-\xf5\xd8\xfc\x01\x95 u\xf4\xa6j\x12\x04Wj\r\x1a\xe8\x9c\x10J\xfbx%\xde\\\xcb\x7f\x12"'
    
    # Convert bytes to integer.Element
    int_elem = bytes_to_integer_element(original_bytes)
    
    # Convert integer.Element back to bytes with original length
    recovered_bytes = integer_element_to_bytes(int_elem, len(original_bytes))
    
    # Output results
    print('Original Bytes:     ', original_bytes)
    print('Integer Element:    ', int_elem)
    print('Recovered Bytes:    ', recovered_bytes)
    print('Match:             ', original_bytes == recovered_bytes)

if __name__ == '__main__':
    test_conversion()


def bytes_to_integer_element_with_size(byte_data):
    # Convert bytes to integer
    int_value = int.from_bytes(byte_data, byteorder='big', signed=False)
    # Store the length of the original byte data
    original_length = len(byte_data)
    # Shift the int_value left by 8 bits (or more) and add the size
    int_with_size = (int_value << (original_length.bit_length() + 7)) | original_length
    return integer(int_with_size)

def integer_element_to_bytes_with_size(int_elem):
    int_value = int(int_elem)
    # Extract the original length
    original_length = int_value & ((1 << 8) - 1)
    # Extract the actual `hed_int` by shifting right
    hed_int = int_value >> (original_length.bit_length() + 7)
    # Convert the integer back to bytes
    return hed_int.to_bytes(original_length, byteorder='big', signed=False)

# Encryption
hed = b'\x00\xbb-\xf5\xd8\xfc\x01\x95 u\xf4\xa6j\x12\x04Wj\r\x1a\xe8\x9c\x10J\xfbx%\xde\\\xcb\x7f\x12"'
hed_int_with_size = bytes_to_integer_element_with_size(hed)

# Decryption
recovered_hed = integer_element_to_bytes_with_size(hed_int_with_size)

print('Original Bytes:     ', hed)
print('Recovered Bytes:    ', recovered_hed)
print('Match:              ', hed == recovered_hed)
