import time
import random
import string
import hashlib
from concurrent.futures import ProcessPoolExecutor
from trie import HexaryTrie  # Correct import for Patricia Trie
import rlp
from eth_utils import keccak

# Configuration
NUM_BLOCKCHAINS = 20  # Number of separate blockchains (shards)
NUM_ENTRIES = 100000  # Total EHRs across all blockchains
NUM_THREADS = 40  # Increase threads for better parallelism
BATCH_SIZE = 1000  # Number of requests per batch
NUM_REQUESTS_LIST = [1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000, 256000, 512000]  # Different request sizes

# Generate random EHR IDs
ehr_ids = ["".join(random.choices(string.ascii_letters + string.digits, k=12)) for _ in range(NUM_ENTRIES)]

# Initialize a Single Blockchain Trie (global storage)
single_blockchain_trie = HexaryTrie(db={})

# Initialize Sharded Blockchain Tries
sharded_blockchain_tries = {f"Blockchain_{i}": HexaryTrie(db={}) for i in range(NUM_BLOCKCHAINS)}

# Function to select a blockchain shard (consistent hashing)
def get_blockchain(ehr_id):
    return f"Blockchain_{int(hashlib.md5(ehr_id.encode()).hexdigest(), 16) % NUM_BLOCKCHAINS}"

# Patricia Trie requires hashed keys for efficient lookup
def hash_key(key):
    return keccak(key.encode())  # Ethereum-style hashing

# Insert EHR into **Single Blockchain Patricia Trie**
def insert_into_single_blockchain(ehr_id):
    cloud_location = f"https://cloud-storage/{ehr_id}"
    single_blockchain_trie[hash_key(ehr_id)] = rlp.encode(cloud_location.encode())

# Insert EHR into **Sharded Blockchain Patricia Trie**
def insert_into_sharded_blockchain(ehr_id):
    blockchain = get_blockchain(ehr_id)
    cloud_location = f"https://cloud-storage/{ehr_id}"
    sharded_blockchain_tries[blockchain][hash_key(ehr_id)] = rlp.encode(cloud_location.encode())

# Query EHR from **Single Blockchain Patricia Trie**
def query_single_blockchain(ehr_id):
    result = single_blockchain_trie.get(hash_key(ehr_id))
    return rlp.decode(result).decode() if result else "EHR not found!"

# Query EHR from **Sharded Blockchain Patricia Trie**
def query_sharded_blockchain(ehr_id):
    blockchain = get_blockchain(ehr_id)
    result = sharded_blockchain_tries[blockchain].get(hash_key(ehr_id))
    return rlp.decode(result).decode() if result else "EHR not found!"

# **Parallel Benchmark for Single Blockchain**
def parallel_single_blockchain_benchmark(num_requests):
    batch_size = BATCH_SIZE
    with ProcessPoolExecutor(max_workers=NUM_THREADS) as executor:
        start_time = time.perf_counter()
        for _ in range(num_requests // batch_size):
            batch_queries = [random.choice(ehr_ids) for _ in range(batch_size)]
            list(executor.map(query_single_blockchain, batch_queries))
        end_time = time.perf_counter()
    elapsed_time = max(end_time - start_time, 1e-6)  # Prevent division by zero
    return num_requests / elapsed_time


# **Parallel Benchmark for Sharded Blockchains**
def parallel_sharded_blockchain_benchmark(num_requests):
    batch_size = BATCH_SIZE
    with ProcessPoolExecutor(max_workers=NUM_THREADS) as executor:
        start_time = time.perf_counter()
        for _ in range(num_requests // batch_size):
            batch_queries = [random.choice(ehr_ids) for _ in range(batch_size)]
            list(executor.map(query_sharded_blockchain, batch_queries))
        end_time = time.perf_counter()
    elapsed_time = max(end_time - start_time, 1e-6)  # Prevent division by zero
    return num_requests / elapsed_time


# **Execute if running as main**
if __name__ == "__main__":
    # Insert sample data
    for ehr_id in ehr_ids:
        insert_into_single_blockchain(ehr_id)
        insert_into_sharded_blockchain(ehr_id)

    # Print Configuration
    print("Configuration:")
    print(f"NUM_BLOCKCHAINS: {NUM_BLOCKCHAINS}")
    print(f"NUM_ENTRIES: {NUM_ENTRIES}")
    print(f"NUM_THREADS: {NUM_THREADS}")
    print(f"BATCH_SIZE: {BATCH_SIZE}")

    # Run Benchmarks for varying request sizes
    results = []
    for num_requests in NUM_REQUESTS_LIST:
        throughput_single_blockchain = parallel_single_blockchain_benchmark(num_requests)
        throughput_sharded_blockchain = parallel_sharded_blockchain_benchmark(num_requests)
        results.append([num_requests, throughput_single_blockchain, throughput_sharded_blockchain])

    # Define the output file name
    output_filename = f"sharding_benchmark_{NUM_BLOCKCHAINS}_bc_2.txt"

    # Open the file for writing
    with open(output_filename, "w") as file:
        # Print and write header
        header = f"{'num_req':<10} {'normal_merkle':<15} {'shard_merkle':<15}\n"
        print(header, end="")  # Print to console
        file.write(header)  # Write to file

        # Print and write results
        for result in results:
            result_line = f"{result[0]:<10} {result[1]:<15.2f} {result[2]:<15.2f}\n"
            print(result_line, end="")  # Print to console
            file.write(result_line)  # Write to file
