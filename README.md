# Holloman3 Fingerprint Plugin for Arkime

Structural malware fingerprinting for HTTP body analysis in packet captures.

## Why Holloman3?

Traditional hashes (MD5, SHA256) break when a single byte changes. Malware authors exploit this — change one byte, get a different hash, evade detection. Holloman3 solves this with a **perceptual hash**: files with similar binary structure produce similar fingerprints.

```
SHA256:  a3fc...1492  ─── single byte change ───  SHA256:  7d12...b8f1
Holloman3: h.8181858176797a78  ─── single byte change ───  Holloman3: h.8181858176797a79
```

A 1-bit difference in Hamming distance between two holloman3 fingerprints means the files are structurally nearly identical — likely variants of the same malware family. This enables:

- **Malware family clustering** — group variants by structural similarity
- **Poly/oligomorphic detection** — catch re-packaged malware that evades SHA-based blocklists
- **Campaign tracking** — link samples across different delivery mechanisms by shared structure
- **Web content fingerprinting** — identify phishing pages cloned from legitimate sites

## Architecture

```
┌─────────────────────┐     ┌──────────────────────┐     ┌──────────────────┐
│   Arkime capture    │     │  holloman3 plugin     │     │   libholloman3    │
│     (http.c)        │────→│  (capture/plugins/)   │────→│   (SIMD kernels)  │
│                     │     │                       │     │                   │
│  HTTP body chunks   │     │  Buffer → Fingerprint │     │  AVX2 / SSE4.1    │
│  from PCAP/network  │     │  Store as ES field    │     │  Hilbert curve    │
└─────────────────────┘     └──────────────────────┘     └──────────────────┘
```

The plugin hooks into Arkime's HTTP parser via `HP_OB` (on body chunk) and `HP_OMC` (on message complete) callbacks. Zero changes to core Arkime code.

## Quick Start

### 1. Build libholloman3

```bash
cd ~/work/ai/libholloman3
make                # builds libholloman3.a + libholloman3.so
make ftest          # run 35 fingerprint pipeline tests
```

### 2. Enable the plugin in Arkime

Add to your Arkime `config.ini`:

```ini
supportHolloman3=true
hollomanCurveOrder=13         # Hilbert curve order 8-16, 13 recommended
hollomanMaxBodyLen=1048576    # Max body bytes to fingerprint (1 MB default)

plugins=holloman.so           # or add holloman to existing plugins list
```

Add to `configure.ac` / `Makefile`:
```makefile
HOLLOMAN3_CFLAGS = -I$(HOME)/work/ai/libholloman3/include
HOLLOMAN3_LIBS   = -L$(HOME)/work/ai/libholloman3 -lholloman3 -lm
```

### 3. Build and run

```bash
./easybutton-build.sh
# or: make && sudo make install
```

The plugin auto-initializes when Arkime starts. HTTP response bodies will be fingerprinted and stored as `http.holloman3.dst` / `http.holloman3.src` fields in Elasticsearch.

### 4. Query fingerprints

```
# Find all sessions with a specific fingerprint
http.holloman3.dst == h.6b718382030b717a0000060700000000

# View fingerprints in session detail
# The "Body Holloman3" column shows h.<32hex> for each HTTP body
```

---

## PCAP Fingerprinting Tool

The standalone tool `tests/fingerprint_pcap.c` extracts HTTP bodies from PCAP files and computes holloman3 fingerprints — useful for offline analysis, malware matching, and threat hunting.

### Build

```bash
cd tests
cc -O2 -std=c99 -D_GNU_SOURCE -Wall \
   -I../../libholloman3/include \
   -o fingerprint_pcap fingerprint_pcap.c \
   -L../../libholloman3 -lholloman3 -lm
```

### Basic usage

```bash
LD_LIBRARY_PATH=../../libholloman3 ./fingerprint_pcap /path/to/capture.pcap
```

Output:
```
PCAP: ver=2.4, snaplen=65536, linktype=1
holloman3: 0.2.0, avx2=1

Server IP       Port   Client IP       Port   Status  BodyLen  Holloman3 (h.<32hex>)                Content-Type
-----------------------------------------------------------------------------------------------------------
10.0.0.1        80     192.168.1.100   52341  200     24598534 h.6b718382030b717a0000060700000000   application/x-msdownload
10.0.0.1        80     192.168.1.100   52342  200     37332326 h.8481827e787d7b7a0f64120700070000   application/x-msdownload

2 HTTP response bodies fingerprinted
```

### Example: Finding structurally similar malware

Capture a PCAP from a malware sandbox or network tap, then:

```bash
# Extract all holloman3 fingerprints from a PCAP
fingerprint_pcap malware-traffic.pcap > fingerprints.txt

# Sort by fingerprint to group similar files visually
sort -k8 fingerprints.txt | less

# Compute Hamming distance between two fingerprints to quantify similarity
python3 -c "
a = '6b718382030b717a0000060700000000'
b = '6b718382030b717b0000060700000000'
dist = sum(bin(int(x,16)^int(y,16)).count('1') for x,y in zip(a,b))
print(f'Hamming distance: {dist} bits')  # small = structurally similar
"
```

Use these fingerprints to:
- **Cluster malware families**: samples with Hamming distance < 32 bits are likely same family
- **Detect new variants**: fingerprint new PCAPs, compare against known-bad fingerprint database
- **Track campaign evolution**: monitor how fingerprints shift as malware is re-packed

### Example: Matching web pages

Capture HTTP traffic to suspicious domains:

```bash
# Fingerprint all response bodies from a phishing investigation PCAP
fingerprint_pcap phishing-campaign.pcap

# Extract unique fingerprints
fingerprint_pcap phishing-campaign.pcap | grep 'h\.' | sort -u -k8 > phishing-fingerprints.txt

# Compare against fingerprints from a legitimate site capture
fingerprint_pcap legitimate-site.pcap | grep 'h\.' | sort -u -k8 > legit-fingerprints.txt

# Find matching structures (phishing clone detection)
comm -12 phishing-fingerprints.txt legit-fingerprints.txt
```

A matching holloman3 fingerprint between a phishing page and the real site means the attacker copied the HTML structure directly — the fingerprints will match even if text, images, and links differ.

---

## Test Suite

```bash
# Run unit tests for the fingerprint pipeline (35 tests)
cd ~/work/ai/libholloman3 && make ftest

# Run integration tests for the HTTP body buffering pattern (8 tests)
cd tests
cc -O2 -std=c99 -Wall -D_GNU_SOURCE \
   -I../../libholloman3/include \
   -o test_http_holloman3 test_http_holloman3.c \
   -L../../libholloman3 -lholloman3 -lm
LD_LIBRARY_PATH=../../libholloman3 ./test_http_holloman3

# Run the PCAP extraction tool (on real capture data)
LD_LIBRARY_PATH=../../libholloman3 ./fingerprint_pcap /path/to/capture.pcap
```

---

## Fingerprint Format

Each fingerprint is a 16-byte binary value rendered as `h.<32 lowercase hex>`:

```
h.6b718382030b717a0000060700000000
  ──────────────────────────────
  32 hex characters (16 bytes)
```

The `h.` prefix identifies it as a holloman3 fingerprint in Arkime field queries.

## Pipeline

```
Raw bytes ──→ Hilbert curve mapping (2-D grid)
                │
                ▼
           Lanczos-3 downsampling (SIMD-accelerated)
                │
                ▼
           90° clockwise rotation
                │
                ▼
           16-byte fingerprint
```

## Requirements

- **CPU**: x86-64 with SSE4.1 (2008+) for production. AVX2 (2013+) for max throughput (~2.5 GB/s).
- **ARM**: NEON support (ARMv8+).
- **Library**: `libholloman3.a` or `.so` in linker path.
- **Arkime**: Any version with plugin system (capture plugins).

## Files

| File | Purpose |
|---|---|
| `capture/plugins/holloman.c` | Arkime capture plugin — buffers HTTP bodies, fingerprints on complete |
| `tests/fingerprint_pcap.c` | Standalone PCAP parser — extracts HTTP bodies and fingerprints them |
| `tests/test_http_holloman3.c` | Integration test — simulates http.c body buffering pattern |
| `~/work/ai/libholloman3/` | The fingerprint library — Hilbert + Lanczos + rotation + SIMD |