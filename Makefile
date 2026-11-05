# arkime-holloman3 — holloman3 HTTP body fingerprint plugin for Arkime capture.
#
# Build requirements:
#   - libholloman3  (set HOLLOMAN3_DIR)
#   - Arkime capture source tree (set ARKIME_DIR)
#   - glib2, OpenSSL dev headers
#
# Targets:
#   make              build the plugin .so (within Arkime tree only)
#   make test         build + run the HTTP body buffering integration test (8 tests)
#   make pcap-tool    build the standalone PCAP body fingerprint extraction tool
#   make pcap-test    run pcap-tool against PCAP=path
#   make clean        remove build artifacts

HOLLOMAN3_DIR ?= $(HOME)/work/ai/libholloman3
ARKIME_DIR    ?= $(HOME)/work/ai/www/arkime

CC            ?= cc
CFLAGS        ?= -O2 -Wall -Wextra -std=c99 -fPIC -D_GNU_SOURCE
INCLUDE        = -I$(HOLLOMAN3_DIR)/include
LDFLAGS        = -L$(HOLLOMAN3_DIR) -lholloman3 -lm

# Plugin build requires the full Arkime capture tree + glib2 headers.
# When ARKIME_DIR is set and glib2 is available, `make` builds the .so.
# Otherwise, build the plugin inside the Arkime tree with ./easybutton-build.sh.
ARKIME_INCLUDE = -I$(ARKIME_DIR)/capture -I$(ARKIME_DIR)/capture/thirdparty \
                $(shell pkg-config --cflags glib-2.0 2>/dev/null)

.PHONY: all plugin test pcap-tool pcap-test clean

.DEFAULT_GOAL := all

all: pcap-tool test
	@echo "Plugin (.so): build inside Arkime tree with ./easybutton-build.sh"
	@echo "  The holloman.c source is in src/  — copy to capture/plugins/ and rebuild."

plugin: holloman.so

holloman.so: src/holloman.c
	$(CC) $(CFLAGS) $(INCLUDE) $(ARKIME_INCLUDE) \
		-shared -o $@ $< $(LDFLAGS)

test: tests/test_http_holloman3
	LD_LIBRARY_PATH=$(HOLLOMAN3_DIR) ./tests/test_http_holloman3

tests/test_http_holloman3: tests/test_http_holloman3.c
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(LDFLAGS)

pcap-tool: tests/fingerprint_pcap

tests/fingerprint_pcap: tests/fingerprint_pcap.c
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(LDFLAGS)

pcap-test: tests/fingerprint_pcap
	LD_LIBRARY_PATH=$(HOLLOMAN3_DIR) ./tests/fingerprint_pcap $(PCAP)

clean:
	rm -f holloman.so tests/test_http_holloman3 tests/fingerprint_pcap