DDIR := $(shell pwd)

SHELL := bash

.phony: install tests

install:
	export "GOBIN=$(DDIR)/build/bin" ; \
	for component in aesz create_wallet view_wallet restore_wallet ; do \
		cd $(DDIR)/cmd/$${component} ; go install ; \
	done

tests:
	test/wallet_test.sh
	test/aesz_test.sh

clean:
	rm -fr ./build
