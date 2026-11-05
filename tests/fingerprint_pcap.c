/* fingerprint_pcap.c — extract HTTP bodies from PCAP, fingerprint with holloman3.
 *
 * Reads a PCAP file, reconstructs TCP streams, extracts HTTP response bodies,
 * and computes holloman3 fingerprints.
 *
 * Build: cc -O2 -std=c99 -D_GNU_SOURCE -Wall -I../../libholloman3/include \
 *            -o fingerprint_pcap fingerprint_pcap.c \
 *            -L../../libholloman3 -lholloman3 -lm
 *
 * Run:   LD_LIBRARY_PATH=../../libholloman3 ./fingerprint_pcap <pcap> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "holloman3.h"

/* ── PCAP file format (little-endian) ────────────────────────────────── */

typedef struct {
    uint32_t magic;
    uint16_t ver_major, ver_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
} __attribute__((packed)) PcapHdr;

typedef struct {
    uint32_t ts_sec, ts_usec;
    uint32_t caplen, origlen;
} __attribute__((packed)) PcapRec;

/* ── Ethernet header ─────────────────────────────────────────────────── */

typedef struct {
    uint8_t  dst[6], src[6];
    uint16_t type;
} __attribute__((packed)) EthHdr;

/* ── IPv4 header ─────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  ver_ihl, dscp_ecn;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl, proto;
    uint16_t checksum;
    uint32_t src, dst;
} __attribute__((packed)) IpHdr;

/* ── TCP header ──────────────────────────────────────────────────────── */

typedef struct {
    uint16_t src_port, dst_port;
    uint32_t seq, ack;
    uint8_t  data_off_res, flags;
    uint16_t window, checksum, urgent;
} __attribute__((packed)) TcpHdr;

/* ── In-memory byte buffer (HTTP body accumulator) ────────────────────── */

#define MAX_BODIES 256

typedef struct {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t *body;
    size_t   body_len;
    size_t   body_cap;
    int      content_length;    /* from HTTP header, -1 if unknown */
    int      is_response;
    int      status_code;
    char     content_type[128];
} HttpFlow;

/* ── Globals ─────────────────────────────────────────────────────────── */

static HttpFlow flows[MAX_BODIES];
static int      nflows = 0;

/* ── Helpers ─────────────────────────────────────────────────────────── */

static int flow_index(uint32_t response_ip, uint16_t response_port,
                       uint32_t request_ip,  uint16_t request_port) {
    for (int i = 0; i < nflows; i++) {
        if (flows[i].is_response &&
            flows[i].src_ip == response_ip  &&
            flows[i].src_port == response_port &&
            flows[i].dst_ip == request_ip   &&
            flows[i].dst_port == request_port)
            return i;
    }
    return -1;
}

static HttpFlow *new_flow(uint32_t src_ip, uint16_t src_port,
                           uint32_t dst_ip, uint16_t dst_port) {
    if (nflows >= MAX_BODIES) return NULL;
    HttpFlow *f = &flows[nflows++];
    memset(f, 0, sizeof(*f));
    f->src_ip   = src_ip;
    f->src_port = src_port;
    f->dst_ip   = dst_ip;
    f->dst_port = dst_port;
    f->content_length = -1;
    f->body_cap  = 65536;
    f->body      = malloc(f->body_cap);
    return f;
}

static void append_body(HttpFlow *f, const uint8_t *data, size_t len) {
    if (f->body_len + len > f->body_cap) {
        while (f->body_len + len > f->body_cap) f->body_cap *= 2;
        f->body = realloc(f->body, f->body_cap);
    }
    memcpy(f->body + f->body_len, data, len);
    f->body_len += len;
}

/* ── HTTP header parser ──────────────────────────────────────────────── */

/* Try to parse the HTTP response header from the start of the body buffer.
 * Looking for: HTTP/1.x <code>\r\n<headers>\r\n\r\n
 * Sets content_length, status_code, is_response, content_type. */
static void try_parse_http_header(HttpFlow *f) {
    if (f->is_response) return;  /* already parsed */

    /* need at least "HTTP/1.x 200\r\n\r\n" (~20 bytes) */
    if (f->body_len < 16) return;

    /* check for HTTP response start line */
    if (memcmp(f->body, "HTTP/", 5) != 0) return;

    /* find first \r\n */
    uint8_t *lf = memmem(f->body, f->body_len, "\r\n", 2);
    if (!lf) return;

    /* parse status code from "HTTP/1.x NNN" */
    char *status_start = (char *)f->body + 9;  /* skip "HTTP/1.x " */
    f->status_code = atoi(status_start);
    f->is_response = 1;

    /* find header end (\r\n\r\n) */
    uint8_t *hdr_start = lf + 2;
    size_t   hdr_remain = f->body_len - (size_t)(hdr_start - f->body);
    uint8_t *hdr_end   = memmem(hdr_start, hdr_remain, "\r\n\r\n", 4);
    if (!hdr_end) return;

    /* scan headers for Content-Length and Content-Type */
    uint8_t *pos = hdr_start;
    while (pos < hdr_end) {
        uint8_t *line_end = memmem(pos, (size_t)(hdr_end - pos), "\r\n", 2);
        if (!line_end) break;

        if (line_end - pos > 16 &&
            strncasecmp((char *)pos, "Content-Length:", 15) == 0) {
            f->content_length = atoi((char *)pos + 15);
        }
        if (line_end - pos > 14 &&
            strncasecmp((char *)pos, "Content-Type:", 13) == 0) {
            size_t n = (size_t)(line_end - (pos + 14));
            if (n > 127) n = 127;
            memcpy(f->content_type, pos + 14, n);
            f->content_type[n] = '\0';
            /* strip leading space */
            char *ct = f->content_type;
            while (*ct == ' ') ct++;
            if (ct != f->content_type) memmove(f->content_type, ct, strlen(ct) + 1);
        }

        pos = line_end + 2;
    }
}

/* ── Packet processing ───────────────────────────────────────────────── */

static void process_packet(const uint8_t *pkt, size_t pkt_len) {
    if (pkt_len < sizeof(EthHdr)) return;
    const EthHdr *eth = (const EthHdr *)pkt;
    if (ntohs(eth->type) != 0x0800) return;   /* not IPv4 */

    if (pkt_len < sizeof(EthHdr) + sizeof(IpHdr)) return;
    const IpHdr *ip = (const IpHdr *)(pkt + sizeof(EthHdr));
    int ip_hdr_len = (ip->ver_ihl & 0x0F) * 4;
    if (ip->proto != 6) return;   /* not TCP */

    size_t ip_payload_off = sizeof(EthHdr) + ip_hdr_len;
    if (pkt_len < ip_payload_off + sizeof(TcpHdr)) return;
    const TcpHdr *tcp = (const TcpHdr *)(pkt + ip_payload_off);
    int tcp_hdr_len = ((tcp->data_off_res >> 4) & 0x0F) * 4;

    size_t payload_off = ip_payload_off + tcp_hdr_len;
    if (payload_off >= pkt_len) return;   /* no payload */
    size_t payload_len = pkt_len - payload_off;
    const uint8_t *payload = pkt + payload_off;

    /* Determine direction: is this from server to client?
     * Heuristic: if source port is 80 or 8080, it's a server response */
    int is_server = (ntohs(tcp->src_port) == 80 || ntohs(tcp->src_port) == 8080);

    uint32_t server_ip   = is_server ? ip->src : ip->dst;
    uint16_t server_port = is_server ? ntohs(tcp->src_port) : ntohs(tcp->dst_port);
    uint32_t client_ip   = is_server ? ip->dst : ip->src;
    uint16_t client_port = is_server ? ntohs(tcp->dst_port) : ntohs(tcp->src_port);

    /* Find or create the flow */
    int idx = flow_index(server_ip, server_port, client_ip, client_port);
    if (idx < 0) {
        HttpFlow *f = new_flow(server_ip, server_port, client_ip, client_port);
        if (!f) return;
        idx = nflows - 1;
    }

    HttpFlow *f = &flows[idx];
    append_body(f, payload, payload_len);
    try_parse_http_header(f);
}

/* ── Main ────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror(argv[1]); return 1; }

    /* Read PCAP header */
    PcapHdr ph;
    if (fread(&ph, sizeof(ph), 1, fp) != 1) {
        fprintf(stderr, "short pcap header\n"); fclose(fp); return 1;
    }
    printf("PCAP: ver=%d.%d, snaplen=%u, linktype=%u\n",
           ph.ver_major, ph.ver_minor, ph.snaplen, ph.linktype);

    /* Init holloman3 */
    if (holloman3_init(13) != 0) {
        fprintf(stderr, "holloman3_init failed\n"); fclose(fp); return 1;
    }
    printf("holloman3: %s, avx2=%d\n\n", holloman3_version(), holloman3_has_avx2());

    /* Allocate packet buffer (snaplen) */
    uint8_t *pkt_buf = malloc(ph.snaplen);
    int n_packets = 0, n_http = 0;

    /* Process packets */
    while (1) {
        PcapRec rec;
        if (fread(&rec, sizeof(rec), 1, fp) != 1) break;

        uint32_t caplen = rec.caplen;
        if (caplen > ph.snaplen) caplen = ph.snaplen;
        if (fread(pkt_buf, caplen, 1, fp) != 1) break;

        process_packet(pkt_buf, caplen);
        n_packets++;
    }

    fclose(fp);

    printf("Processed %d packets, %d TCP flows\n\n", n_packets, nflows);

    /* Print results for HTTP response flows with bodies */
    printf("%-15s %-6s %-15s %-6s %-7s %-8s %-36s %s\n",
           "Server IP", "Port", "Client IP", "Port",
           "Status", "BodyLen", "Holloman3 (<c>.<32hex>)", "Content-Type");
    printf("%.*s\n", 150,
           "--------------------------------------------------------------------------------------------------------------------------------------------------------");

    for (int i = 0; i < nflows; i++) {
        HttpFlow *f = &flows[i];
        if (!f->is_response) continue;

        /* Body is everything after the HTTP header */
        uint8_t *hdr_end = memmem(f->body, f->body_len, "\r\n\r\n", 4);
        size_t body_start = hdr_end ? (size_t)(hdr_end + 4 - f->body) : 0;
        size_t body_len   = f->body_len - body_start;

        if (body_len == 0) continue;
        n_http++;

        /* Print flow info */
        struct in_addr sa, ca;
        sa.s_addr = f->src_ip; ca.s_addr = f->dst_ip;
        printf("%-15s %-6d %-15s %-6d %-7d %-8zu ",
               inet_ntoa(sa), f->src_port,
               inet_ntoa(ca), f->dst_port,
               f->status_code, body_len);

        /* Compute holloman3 fingerprint of the body */
        uint8_t fp[16];
        if (holloman3_fingerprint_buffer(f->body + body_start, body_len, fp) == 0) {
            char id[35];
            holloman3_fingerprint_string(fp, id);
            printf("%-36s ", id);
        } else {
            printf("%-36s ", "ERR");
        }

        /* Content-Type */
        printf("%s\n", f->content_type[0] ? f->content_type : "(unknown)");
    }

    printf("\n%d HTTP response bodies fingerprinted\n", n_http);

    /* Free body buffers */
    for (int i = 0; i < nflows; i++)
        free(flows[i].body);

    holloman3_cleanup();
    return 0;
}