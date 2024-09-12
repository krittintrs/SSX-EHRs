import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import ProcessPoolExecutor

def hash_data(data):
    """Hash a piece of data using SHA-256."""
    return hashlib.sha256(data.encode()).hexdigest()

class MerkleTree:
    def __init__(self, leaves):
        """Initialize the Merkle Tree with leaf nodes."""
        self.leaves = leaves
        self.tree = self._build_tree(leaves)

    def _build_tree(self, leaves):
        """Build the Merkle Tree and return the tree structure."""
        tree = []
        current_level = [hash_data(leaf) for leaf in leaves]
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1] if i+1 < len(current_level) else left
                next_level.append(hash_data(left + right))
            tree.append(next_level)
            current_level = next_level
        return tree

    def get_root(self):
        """Get the root hash of the Merkle Tree."""
        return self.tree[-1][0] if self.tree else None

    def search(self, leaf_hash):
        """Simulate a search by looking for the hash in the tree."""
        return any(leaf_hash == hash_data(leaf) for leaf in self.leaves)

def create_merkle_tree(num_leaves):
    """Create a Merkle Tree with a specified number of leaves."""
    leaves = [f"EncEHR{i}" for i in range(num_leaves)]
    tree = MerkleTree(leaves)
    return tree

def concurrent_searches(tree, num_searches):
    """Perform concurrent searches on the Merkle Tree."""
    leaf_hash = hash_data("EncEHR500")  # Example search target
    with ProcessPoolExecutor(max_workers=200) as executor:
        futures = [executor.submit(tree.search, leaf_hash) for _ in range(num_searches)]
        return sum(f.result() for f in futures)

def throughput_test(num_leaves, search_requests):
    """Run the throughput test on the Merkle Tree."""
    # Step 1: Create a Merkle Tree with 100k nodes
    print("Creating Merkle Tree with 100k nodes...")
    start_time = time.time()
    tree = create_merkle_tree(num_leaves)
    creation_time = time.time() - start_time
    print(f"Tree created in {creation_time:.2f} seconds.")
    
    # Step 2: Perform search requests
    for num_requests in search_requests:
        print(f"\nRunning throughput test with {num_requests} concurrent searches...")
        start_time = time.time()
        successful_searches = concurrent_searches(tree, num_requests)
        duration = time.time() - start_time
        
        # Calculate transactions per second (throughput)
        tps = num_requests / duration
        print(f"Processed {num_requests} concurrent searches in {duration:.2f} seconds.")
        print(f"Throughput: {tps:.2f} transactions per second (TPS)")
        print(f"Successful searches: {successful_searches}/{num_requests}")

if __name__ == "__main__":
    num_leaves = 100000  # 100k nodes
    search_requests = [500, 1000, 2000, 4000, 8000]  # Increasing concurrent search requests
    
    throughput_test(num_leaves, search_requests)
