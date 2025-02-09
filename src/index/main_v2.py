import time
import random
import string
import hashlib
from pytrie import StringTrie  

# Configuration
NUM_ENTRIES = 100000  # Number of total EHRs
NUM_REQUESTS = 100  # Number of lookups for benchmarking
hospitals = ["HOSP1", "HOSP2", "HOSP3"]

# Generate random ehr_id and hospital IDs
ehr_ids = ["".join(random.choices(string.ascii_letters + string.digits, k=12)) for _ in range(NUM_ENTRIES)]
data_list = []  # Simulating blockchain full scan (instead of a dictionary)
cloud_storage = {}  # Simulated cloud storage

# Simulated Blockchain Index storing hospital Merkle roots
blockchain_index = {}

# Create an optimized Merkle Patricia Trie
merkle_trie = StringTrie()

# Function to hash data (SHA-256 for security)
def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Function to insert an encrypted EHR into the system
def insert_ehr():
    ehr_id = random.choice(ehr_ids)
    hid = random.choice(hospitals)
    cloud_location = f"https://cloud-storage/{ehr_id}"

    # Store encrypted EHR in cloud
    cloud_storage[ehr_id] = f"FIN_EncEHRpid_{ehr_id}"

    # Simulated blockchain (slow search: must scan `data_list`)
    data_list.append({"ehr_id": ehr_id, "hid": hid, "cloud_location": cloud_location})

    # Insert into Merkle Patricia Trie (fast search)
    merkle_trie[ehr_id] = {"hid": hid, "cloud_location": cloud_location}

    # Compute Merkle root and update blockchain index
    merkle_root = hash_data(ehr_id + cloud_location)
    blockchain_index[hid] = merkle_root

# Function to retrieve an encrypted EHR using **Traditional Blockchain Search (Full Scan)**
def traditional_blockchain_search(_):
    ehr_id = random.choice(ehr_ids)
    
    # Mimicking a blockchain search: Full database scan (`O(N)`)
    for record in data_list:
        if record["ehr_id"] == ehr_id:
            return record  # Found the matching record
    return "EHR not found!"

# Function to retrieve an encrypted EHR using **Optimized Merkle Patricia Trie**
def merkle_trie_query(_):
    ehr_id = random.choice(ehr_ids)
    ehr_info = merkle_trie.get(ehr_id, None)
    if not ehr_info:
        return "EHR not found!"
    
    hid = ehr_info["hid"]
    cloud_location = ehr_info["cloud_location"]

    # Validate with Blockchain Index
    if blockchain_index.get(hid) == hash_data(ehr_id + cloud_location):
        return f"EHR Location: {cloud_location}"
    else:
        return "Data Integrity Compromised!"

# Benchmarking Function
def benchmark(func, num_requests=NUM_REQUESTS):
    start_time = time.perf_counter()
    for _ in range(num_requests):
        func(None)  # We pass None since the function takes one argument
    end_time = time.perf_counter()
    return num_requests / (end_time - start_time)  # Requests per second

# Insert sample data
for _ in range(NUM_ENTRIES):
    insert_ehr()

# Run Benchmarks
throughput_traditional = benchmark(traditional_blockchain_search)
throughput_merkle = benchmark(merkle_trie_query)

# Print Results
print(f"Traditional Blockchain Search Throughput (Full Scan): {throughput_traditional:.2f} requests/sec")
print(f"Optimized Merkle Patricia Trie Search Throughput: {throughput_merkle:.2f} requests/sec")

