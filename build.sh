set -e

OPENSSL_VERSION="3.5.5"
CWD=$(pwd)

# Activate virtualenv (create if not exists)
if [ ! -d "env" ]; then
    virtualenv env
fi
. env/bin/activate

# Install build dependencies
pip install -U setuptools wheel pip
pip install cffi pycparser
pip install "maturin>=1.9.4,<2"

# Build OpenSSL (skip if already built)
if [ ! -f "${CWD}/openssl/lib64/libssl.a" ]; then
    if [ ! -f "openssl-${OPENSSL_VERSION}.tar.gz" ]; then
        curl -LO https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
    fi
    tar xzvf openssl-${OPENSSL_VERSION}.tar.gz
    cd openssl-${OPENSSL_VERSION}
    ./config no-shared no-ssl3 -fPIC --prefix=${CWD}/openssl
    make -j$(nproc) && make install
    cd ..
fi

# Build cryptography from local source with static OpenSSL
OPENSSL_DIR="${CWD}/openssl" OPENSSL_STATIC=1 pip wheel --no-cache-dir --no-binary cryptography .

