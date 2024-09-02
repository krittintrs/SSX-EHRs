import os
import subprocess 


CPABE_PATH = './cpabe-0.11'
KEY_PATH = './key'


def setup_cpabe():
    cpabe_setup_path = os.path.join(CPABE_PATH, 'cpabe-setup')
    subprocess.run([cpabe_setup_path], check=True)

# Function to generate the private key using cpabe-keygen
def generate_private_key(attributes, priv_name):
    priv_key_path = os.path.join(KEY_PATH, priv_name)
    pub_key_path = os.path.join(KEY_PATH,'pub_key')
    master_key_path = os.path.join(KEY_PATH,'master_key')
    cpabe_keygen_path = os.path.join(CPABE_PATH, 'cpabe-keygen')
    subprocess.run([cpabe_keygen_path, '-o', priv_key_path, pub_key_path, master_key_path] + attributes, check=True)


def main():
    # setup_cpabe()
    
    attributes = ['A', 'B', 'E']
    priv_name = 'test_priv'

    generate_private_key(attributes,priv_name)

if __name__ == '__main__':
    main()