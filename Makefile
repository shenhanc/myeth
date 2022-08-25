DDIR := $(shell pwd)

SHELL := bash
MODPATH := github.com/shenhanc/myeth

PKGS := aesz client
CMDS := aesz create_wallet view_wallet restore_wallet

.phony: install tests

libs:
	go install $(foreach l,$(PKGS),$(MODPATH)/pkg/$(l))

cmds:
	go install $(foreach c, $(CMDS),$(MODPATH)/cmd/$(c))

tests:
	test/wallet_test.sh
	test/aesz_test.sh

clean:
	rm -fr ./build
