import os

def create_test_files(file_sizes):
    for size in file_sizes:
        with open(f'./input/input_file_{size}.bin', 'wb') as f:
            f.write(os.urandom(size))
        print(f'Create test file with size {size}: done')

file_sizes = [100_000, 500_000, 2_000_000, 10_000_000, 50_000_000]  # Sizes in bytes (100KB, 500KB, 2MB, 10MB, 50MB)
create_test_files(file_sizes)
