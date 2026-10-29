# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Building SlateOS. `make` builds both install media:
#
#   target/slate-usb.img   for USB sticks (written raw, with dd or GNOME Disks)
#   target/slate.iso       for DVDs and virtual machines
#
# `make help` lists the other targets. Everything is built by
# `cargo xtask` (tools/xtask); this file only gives it short names.

CARGO ?= cargo
XTASK := $(CARGO) xtask

.DEFAULT_GOAL := all
.PHONY: all usb iso run run-usb test check deps clean help

all: usb iso ## Build both install media (the USB image and the ISO)
	@echo
	@echo "SlateOS is built:"
	@echo "  target/slate-usb.img  write it to a USB stick (see guides/INSTALL.md)"
	@echo "  target/slate.iso      for DVDs and virtual machines"

usb: deps ## Build the USB install image: target/slate-usb.img
	$(XTASK) usb --release

iso: deps ## Build the hybrid ISO: target/slate.iso
	$(XTASK) iso --release

run: deps ## Boot SlateOS in QEMU (UEFI); Ctrl-A X quits
	@tools/check-deps.sh --run
	$(XTASK) run

run-usb: usb ## Try the USB image in a QEMU window, with a virtual disk to install on
	@tools/check-deps.sh --run
	$(XTASK) try-install

test: deps ## Run the test suite in QEMU (takes a while)
	@tools/check-deps.sh --run
	$(XTASK) test

check: deps ## Formatting, lints and the host tests
	$(XTASK) check

deps: ## Check that the tools the build needs are installed
	@tools/check-deps.sh

clean: ## Remove everything built (target/)
	$(CARGO) clean

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-9s %s\n", $$1, $$2}'
