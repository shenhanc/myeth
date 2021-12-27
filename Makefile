DDIR := $(shell pwd)

SHELL := bash

install:
	if [[ ! -d "$${INSTALL_PREFIX}" ]]; then echo "Invalid INSTALL_PREFIX: $${INSTALL_PREFIX}" ; exit 1; fi
	export "GOBIN=$${INSTALL_PREFIX}" ; \
	for component in create_wallet view_wallet restore_wallet ; do \
		cd $(DDIR)/cmd/$${component} ; go install ; \
	done

wallet_test:
	test/wallet_test.sh
