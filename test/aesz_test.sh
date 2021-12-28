#!/bin/bash

set -eu

DDIR="$(cd $(dirname "$0"); pwd)"

TESTDIR="$(mktemp --directory --tmpdir="${DDIR}" test.XXXXXX)"

export GOBIN="${TESTDIR}/bin"

declare -a binaries=( aesz )
for d in "${binaries[@]}"; do 
    cd "${DDIR}"/../cmd/${d}; go install
done

echo "Installed \"${binaries[@]}\" into ${GOBIN}"

cd "${TESTDIR}"

declare -a test_data_size=(0 1 2 3 4 5 1024 1025 1098 1048576 1048590 3145728 3145729)
# declare -a test_data_size=(1024)

for s in "${test_data_size[@]}"; do
    echo "Testing enc/dec ${s} bytes files ..."
    origin="test.data${s}"
    head -c ${s} /dev/random > "${origin}"
    bin/aesz --enc --in ${origin} --out ${origin}.enc --passphrase 123456abc
    if diff ${origin}.enc ${origin} 1>/dev/null 2>&1 ; then
        echo "enc failed"
        exit 1
    fi
    bin/aesz --dec --in ${origin}.enc --out ${origin}.dec --passphrase 123456abc
    if ! diff ${origin} ${origin}.dec ; then
        echo "dec failed"
        exit 1
    fi
done