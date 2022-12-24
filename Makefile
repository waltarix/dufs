ifeq ($(RUST_TARGET),)
	TARGET :=
	RELEASE_SUFFIX :=
else
	TARGET := $(RUST_TARGET)
	RELEASE_SUFFIX := -$(TARGET)
	export CARGO_BUILD_TARGET = $(RUST_TARGET)
endif

PROJECT_NAME := dufs

_HASH   := \#
VERSION := $(lastword $(subst @, ,$(subst $(_HASH), ,$(shell cargo pkgid))))
RELEASE := $(PROJECT_NAME)-$(VERSION)$(RELEASE_SUFFIX)

DIST_DIR := dist
RELEASE_DIR := $(DIST_DIR)/$(RELEASE)

BINARY := target/$(TARGET)/release/$(PROJECT_NAME)

RELEASE_BINARY := $(RELEASE_DIR)/$(PROJECT_NAME)

ARTIFACT := $(RELEASE).tar.xz

.PHONY: all
all: $(ARTIFACT)

$(BINARY):
	cargo build --locked --release

$(DIST_DIR) $(RELEASE_DIR):
	mkdir -p $@

$(RELEASE_BINARY): $(BINARY) $(RELEASE_DIR)
	cp -f $< $@

$(ARTIFACT): $(RELEASE_BINARY)
	tar -C $(DIST_DIR) -Jcvf $@ $(RELEASE)

.PHONY: clean
clean:
	$(RM) -rf $(ARTIFACT) $(DIST_DIR)
