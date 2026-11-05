/* holloman.c — Arkime capture plugin for holloman3 HTTP body fingerprinting.
 *
 * Buffers HTTP response bodies as they arrive (HP_OB callback) and computes
 * a 16-byte holloman3 structural fingerprint on message complete (HP_OMC).
 * The fingerprint is stored as "h.<32 hex>" in http.holloman3 direction fields.
 *
 * Uses libholloman3 for Hilbert-curve mapping + Lanczos-3 SIMD downsampling.
 *
 * Configuration (config.ini):
 *   supportHolloman3=true       enable the plugin
 *   hollomanCurveOrder=13       Hilbert curve order (8-16)
 *   hollomanMaxBodyLen=1048576  max body bytes to fingerprint */

#include "arkime.h"
#include "holloman3.h"

extern ArkimeConfig_t config;

/* ── plugin globals ──────────────────────────────────────────────────── */

LOCAL int holloman_plugin_num;
LOCAL int holloman_field[2];           /* 0=src(request), 1=dst(response) */
LOCAL int holloman_max_body_len;
LOCAL int holloman_enabled;

/* ── per-session data ────────────────────────────────────────────────── */

typedef struct {
    GByteArray *body[2];               /* buffered body per direction */
} HollomanData_t;

/* ── HP_OB: buffer each body chunk ───────────────────────────────────── */

LOCAL void holloman_hp_ob(ArkimeSession_t *session, http_parser *hp,
                          const char *at, size_t length)
{
    if (!holloman_enabled || !session || length == 0)
        return;

    HollomanData_t *hd = session->pluginData[holloman_plugin_num];
    if (!hd) {
        hd = ARKIME_TYPE_ALLOC0(HollomanData_t);
        session->pluginData[holloman_plugin_num] = hd;
        hd->body[0] = g_byte_array_new();
        hd->body[1] = g_byte_array_new();
    }

    /* direction: 0=request (has method), 1=response (has status_code) */
    int dir = (hp->status_code > 0) ? 1 : 0;

    if (hd->body[dir]->len >= (guint)holloman_max_body_len)
        return;

    size_t room = holloman_max_body_len - hd->body[dir]->len;
    g_byte_array_append(hd->body[dir], (const guint8 *)at,
                        length < room ? length : room);
}

/* ── HP_OMC: fingerprint the complete body ───────────────────────────── */

LOCAL void holloman_hp_omc(ArkimeSession_t *session, http_parser *hp)
{
    if (!holloman_enabled || !session)
        return;

    HollomanData_t *hd = session->pluginData[holloman_plugin_num];
    if (!hd)
        return;

    int dir = (hp->status_code > 0) ? 1 : 0;

    if (hd->body[dir]->len == 0)
        return;

    uint8_t fp[16];
    if (holloman3_fingerprint_buffer(hd->body[dir]->data,
                                      hd->body[dir]->len, fp) == 0) {
        char id[35];   /* <c>.<32hex> + null */
        holloman3_fingerprint_string(fp, id);

        arkime_field_string_add(holloman_field[dir], session,
                                id, 34, TRUE);
    }

    g_byte_array_set_size(hd->body[dir], 0);
}

/* ── SAVE: cleanup per-session state ─────────────────────────────────── */

LOCAL void holloman_save(ArkimeSession_t *session, int final)
{
    HollomanData_t *hd = session->pluginData[holloman_plugin_num];
    if (!hd)
        return;

    if (final) {
        if (hd->body[0]) g_byte_array_unref(hd->body[0]);
        if (hd->body[1]) g_byte_array_unref(hd->body[1]);
        ARKIME_TYPE_FREE(HollomanData_t, hd);
        session->pluginData[holloman_plugin_num] = 0;
    } else {
        /* mid-save: reset buffers for next period, keep allocation */
        for (int dir = 0; dir < 2; dir++) {
            if (hd->body[dir])
                g_byte_array_set_size(hd->body[dir], 0);
        }
    }
}

/* ── plugin init ─────────────────────────────────────────────────────── */

void arkime_plugin_init()
{
    holloman_enabled = arkime_config_boolean(NULL, "supportHolloman3", FALSE);
    if (!holloman_enabled)
        return;

    int order = arkime_config_int(NULL, "hollomanCurveOrder", 13, 8, 16);
    if (holloman3_init((uint32_t)order) != 0) {
        LOG("ERROR: holloman3 init failed — disabling plugin");
        holloman_enabled = 0;
        return;
    }
    LOG("holloman3 initialized (order=%d, avx2=%d)",
        order, holloman3_has_avx2());

    holloman_max_body_len = arkime_config_int(NULL, "hollomanMaxBodyLen",
                                               1048576, 0, 268435456);

    holloman_plugin_num = arkime_plugins_register("holloman", TRUE);

    /* register HTTP body and message-complete callbacks */
    arkime_plugins_set_http_cb("holloman",
        NULL,                /* on_message_begin    */
        NULL,                /* on_url              */
        NULL,                /* on_header_field     */
        NULL,                /* on_header_value     */
        NULL,                /* on_headers_complete */
        holloman_hp_ob,      /* on_body             */
        holloman_hp_omc);    /* on_message_complete */

    /* register save callback for session cleanup */
    arkime_plugins_set_cb("holloman",
        NULL, NULL, NULL,    /* ip, udp, tcp       */
        NULL,                /* preSave             */
        holloman_save,       /* save                */
        NULL, NULL, NULL);   /* new, exit, reload   */

    holloman_field[0] = arkime_field_define("http", "lotermfield",
        "http.holloman3.src", "HTTP Src Body Holloman3",
        "http.src.holloman3",
        "Holloman3 perceptual fingerprint of HTTP request body",
        ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
        "category", "holloman3",
        (char *)NULL);

    holloman_field[1] = arkime_field_define("http", "lotermfield",
        "http.holloman3.dst", "HTTP Dst Body Holloman3",
        "http.dst.holloman3",
        "Holloman3 perceptual fingerprint of HTTP response body",
        ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
        "category", "holloman3",
        (char *)NULL);

    LOG("holloman plugin ready (max_body=%d)", holloman_max_body_len);
}