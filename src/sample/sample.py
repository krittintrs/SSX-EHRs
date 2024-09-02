import os

def create_test_files(file_sizes):
    for size in file_sizes:
        with open(f'./input/input_file_{size}.bin', 'wb') as f:
            f.write(os.urandom(size))
        print(f'Create test file with size {size}: done')

file_sizes = [50_000, 100_000, 200_000, 400_000, 800_000, 1_600_000]
create_test_files(file_sizes)
