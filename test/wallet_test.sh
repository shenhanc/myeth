#!/bin/bash

set -eu

DDIR="$(cd $(dirname "$0"); pwd)"

TESTDIR="$(mktemp --directory --tmpdir="${DDIR}" test.XXXXXX)"

export GOBIN="${TESTDIR}/bin"

declare -a wallet_binaries=( create_wallet restore_wallet view_wallet )
for d in "${wallet_binaries[@]}"; do 
    cd "${DDIR}"/../cmd/${d}; go install
done

echo "Installed \"${wallet_binaries[@]}\" into ${GOBIN}"

cd "${TESTDIR}"
echo "Creating wallet ..."
bin/create_wallet --passphrase=123456 --keystore=keystore --wordlist=chinese 1>create.log 2>&1

wallet_file="$(sed -nEe 's!^Wallet file: (.*)$!\1!p' create.log)"
mnemonic="$(sed -nEe 's!^Mnemonic: (.*)$!\1!p' create.log)"

echo "Restoring wallet using menmonic..."
echo "${mnemonic}" > mnemonic.input
bin/restore_wallet --mnemonic_file=mnemonic.input --keystore=restored_keystore --passphrase=abcdefg --wordlist=chinese \
    1>restore.log 2>&1
restored_wallet_file="$(sed -nEe 's!^Restored wallet into file: (.*)$!\1!p' restore.log)"

echo "Comparing wallets ..."

bin/view_wallet --wallet="${wallet_file}" --passphrase=123456 1>dump.1 2>&1
bin/view_wallet --wallet="${restored_wallet_file}" --passphrase=abcdefg 1>dump.2 2>&1

if diff dump.1 dump.2; then
    echo "${wallet_file} and ${restored_wallet_file} are the same (encrypted with different passphrases)"
    echo "Test succeeded"
    rm -fr ${TESTDIR}
else
    echo "Test failed"
    exit 1
fi
