# SSX-EHRs
## References
- Scheme 4: 
- Scheme 5: https://github.com/xuehuan-yang/VFPPBA

## Environment Installation

### MacOS

Library Installation
```bash
brew install openssl
brew install gmp
brew install pbc
```

`charm` Installation

```bash
git clone https://github.com/JHUISI/charm.git
cd charm
./configure.sh --python={python_path} --enable-darwin

export CFLAGS="-I/opt/homebrew/include"
export LDFLAGS="-L/opt/homebrew/lib"
python setup.py install

make install
```

### Linux

System Installation
```bash
sudo apt-get install git tree
sudo apt-get install zstd flex bison gcc build-essential python3-pip
sudo apt-get install python3-setuptools python3-dev libssl-dev
```

charm Installation 
```bash
cd ~/alphabet/charm/
git clone https://github.com/xuehuan-yang/VFPPBA.git
git clone https://github.com/xuehuan-yang/PSME.git

cd ~/alphabet/software/
wget https://repo.anaconda.com/archive/Anaconda3-2021.11-Linux-x86_64.sh
bash Anaconda3-2021.11-Linux-x86_64.sh 
(-> ENTER*100times -> yes -> PREFIX=/home/apollo/anaconda3)
source ~/.bashrc
```

conda setup (can also use virtualenv)
```bash
conda create -n charm python=3.10.12
conda activate charm
conda install -c anaconda pycrypto
conda install -c menpo opencv  
conda install -c conda-forge matplotlib
pip install pyparsing==2.4.6
```

openssl
```bash
conda activate charm
cd ~/alphabet/charm/
wget https://www.openssl.org/source/openssl-1.1.1n.tar.gz
tar -zxvf openssl-1.1.1n.tar.gz
cd ~/alphabet/charm/openssl-1.1.1n/
./config
make 
sudo make install
dpkg -l | grep openssl
```

gmp
```bash
conda activate charm
cd ~/alphabet/charm/
wget https://gmplib.org/download/gmp/gmp-6.2.1.tar.zst
tar -I zstd -xvf gmp-6.2.1.tar.zst
cd gmp-6.2.1/
./configure
make
make check
sudo make install
dpkg -l | grep gmp
```

pbc
```bash
conda activate charm
cd ~/alphabet/charm/
wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xvf pbc-0.5.14.tar.gz
cd pbc-0.5.14/
./configure
make
sudo make install
sudo ldconfig
dpkg -l | grep pbc
```

enable charm in conda
```bash
conda activate charm
cd ~/alphabet/charm/
git clone https://github.com/JHUISI/charm.git
cd charm/
sudo ./configure.sh
sudo ./configure.sh --python={python_path}

make
sudo make install
sudo ldconfig /usr/local/lib64/ 
sudo ldconfig /usr/local/lib/

cd ~/alphabet/charm/
rm -rf openssl-1.1.1n.tar.gz
rm -rf gmp-6.2.1.tar.zst
rm -rf pbc-0.5.14.tar.gz
```

## Python Library

```bash
pip install -r requirements.txt
```

