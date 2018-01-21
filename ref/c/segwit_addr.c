/* Copyright (c) 2017 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include <time.h>
#include <assert.h>

#include "mbedtls/sha256.h"

#include "segwit_addr.h"

uint32_t bech32_polymod_step(uint32_t pre) {
    uint8_t b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5) ^
        (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
        (-((b >> 1) & 1) & 0x26508e6dUL) ^
        (-((b >> 2) & 1) & 0x1ea119faUL) ^
        (-((b >> 3) & 1) & 0x3d4233ddUL) ^
        (-((b >> 4) & 1) & 0x2a1462b3UL);
}

static const char charset[] = {
    'q', 'p', 'z', 'r', 'y', '9', 'x', '8',
    'g', 'f', '2', 't', 'v', 'd', 'w', '0',
    's', '3', 'j', 'n', '5', '4', 'k', 'h',
    'c', 'e', '6', 'm', 'u', 'a', '7', 'l'
};
static const char hrp_str[][5] = {
    { 'b', 'c', '\0' },
    { 't', 'b', '\0' },
    { 'B', 'C', '\0' },
    { 'T', 'B', '\0' },
    { 'l', 'n', 'b', 'c', '\0' },
    { 'l', 'n', 't', 'b', '\0' }
};
static const uint32_t k_chk[] = {
    0x2318043, 0x2318282, 0x1772d71a, 0x1772d5db
};
static const int8_t charset_rev[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

/** Encode a Bech32 string
 *
 *  Out: output:  Pointer to a buffer of size strlen(hrp) + data_len + 8 that
 *                will be updated to contain the null-terminated Bech32 string.
 *  In: hrp :     Pointer to the non-null-terminated human readable part(length=2).
 *      hrp_chk:  pre-calculated chk
 *      data :    Pointer to an array of 5-bit values.
 *      data_len: Length of the data array.
 *  Returns true if successful.
 */
static bool bech32_encode(char *output, const char *hrp, uint32_t hrp_chk, const uint8_t *data, size_t data_len) {
    uint32_t chk = hrp_chk;
    size_t i;
    while (*hrp != '\0') {
        *(output++) = *(hrp++);
    }
    *(output++) = '1';
    for (i = 0; i < data_len; ++i) {
        if (*data >> 5) return false;
        chk = bech32_polymod_step(chk) ^ (*data);
        *(output++) = charset[*(data++)];
    }
    for (i = 0; i < 6; ++i) {
        chk = bech32_polymod_step(chk);
    }
    chk ^= 1;
    for (i = 0; i < 6; ++i) {
        *(output++) = charset[(chk >> ((5 - i) * 5)) & 0x1f];
    }
    *output = 0;
    return true;
}

/** Decode a Bech32 string
 *
 *  Out: hrp:      Pointer to a buffer of size strlen(input) - 6. Will be
 *                 updated to contain the null-terminated human readable part.
 *       data:     Pointer to a buffer of size strlen(input) - 8 that will
 *                 hold the encoded 5-bit data values.
 *       data_len: Pointer to a size_t that will be updated to be the number
 *                 of entries in data.
 *  In: input:     Pointer to a null-terminated Bech32 string.
 *  Returns true if succesful.
 */
static bool bech32_decode(char* hrp, uint8_t *data, size_t *data_len, const char *input, bool ln) {
    uint32_t chk = 1;
    size_t i;
    size_t input_len = strlen(input);
    size_t hrp_len;
    int have_lower = 0, have_upper = 0;
    if (ln) {
        if (input_len < (4 + 1 + 7 + 104 + 6)) {
            return false;
        }
    } else {
        if ((input_len < 8) || (90 < input_len)) {
            return false;
        }
    }
    *data_len = 0;
    while (*data_len < input_len && input[(input_len - 1) - *data_len] != '1') {
        ++(*data_len);
    }
    hrp_len = input_len - (1 + *data_len);
    if (hrp_len < 1 || *data_len < 6) {
        return false;
    }
    *(data_len) -= 6;
    for (i = 0; i < hrp_len; ++i) {
        int ch = input[i];
        if (ch < 33 || ch > 126) {
            return false;
        }
        if (ch >= 'a' && ch <= 'z') {
            have_lower = 1;
        } else if (ch >= 'A' && ch <= 'Z') {
            have_upper = 1;
            ch = (ch - 'A') + 'a';
        }
        hrp[i] = ch;
        chk = bech32_polymod_step(chk) ^ (ch >> 5);
    }
    hrp[i] = 0;
    chk = bech32_polymod_step(chk);
    for (i = 0; i < hrp_len; ++i) {
        chk = bech32_polymod_step(chk) ^ (input[i] & 0x1f);
    }
    ++i;
    while (i < input_len) {
        int v = (input[i] & 0x80) ? -1 : charset_rev[(int)input[i]];
        if (input[i] >= 'a' && input[i] <= 'z') have_lower = 1;
        if (input[i] >= 'A' && input[i] <= 'Z') have_upper = 1;
        if (v == -1) {
            return false;
        }
        chk = bech32_polymod_step(chk) ^ v;
        if (i + 6 < input_len) {
            data[i - (1 + hrp_len)] = v;
        }
        ++i;
    }
    if (have_lower && have_upper) {
        return false;
    }
    return chk == 1;
}

//inの先頭からinbitsずつ貯めていき、outbitsを超えるとその分をoutに代入していく
//そのため、
//  inbits:5
//  in [01 0c 12 1f1c 19 02]
//  outbits:8
//とした場合、out[0x0b 0x25 0xfe 0x64 0x40]が出ていく。
//最後の0x40は最下位bitの0数はinbitsと同じなため、[0x59 x92f 0xf3 0x22]とはならない。
//その場合は、64bitまでであればconvert_be64()を使用する。
static bool convert_bits(uint8_t* out, size_t* outlen, int outbits, const uint8_t* in, size_t inlen, int inbits, bool pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
            //printf("bits:%d\n", bits);
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return false;
    }
    return true;
}

//inbits:5, outbits:8で64bitまで変換可能
static uint64_t convert_be64(const uint8_t *p_data, size_t dlen)
{
    uint64_t ret = 0;
    for (size_t lp = 0; lp < dlen; lp++) {
        ret <<= 5;
        ret |= p_data[lp];
    }
    return ret;
}

//32進数として変換
static uint64_t convert_32(const uint8_t *p_data, size_t dlen)
{
    uint64_t ret = 0;
    for (size_t lp = 0; lp < dlen; lp++) {
        ret *= (uint64_t)32;
        ret += (uint64_t)p_data[lp];
    }
    return ret;
}

static bool analyze_tag(size_t *p_len, const uint8_t *p_tag, ln_invoice_t *p_invoice_data)
{
    fprintf(stderr, "------------------\n");
    uint8_t tag = *p_tag;
    switch (tag) {
    case 1:
        fprintf(stderr, "payment_hash\n");
        break;
    case 13:
        fprintf(stderr, "purpose of payment(ASCII)\n");
        break;
    case 19:
        fprintf(stderr, "pubkey of payee node\n");
        break;
    case 23:
        fprintf(stderr, "purpose of payment(SHA256)\n");
        break;
    case 6:
        fprintf(stderr, "expiry second\n");
        break;
    case 24:
        fprintf(stderr, "min_final_cltv_expiry\n");
        break;
    case 9:
        fprintf(stderr, "Fallback on-chain\n");
        break;
    case 3:
        fprintf(stderr, "extra routing info\n");
        break;
    default:
        fprintf(stderr, "unknown tag: %02x\n", *p_tag);
        break;
    }
    int len = p_tag[1] * 0x20 + p_tag[2];
    fprintf(stderr, "  len=%d\n", len);
    p_tag += 3;
    uint8_t *p_data = (uint8_t *)malloc((len * 5 + 7) / 8); //確保サイズは切り上げ
    size_t d_len = 0;
    switch (tag) {
    case 13:
        //purpose of payment(ASCII)
        if (!convert_bits(p_data, &d_len, 8, p_tag, len, 5, true)) return false;
        d_len =  (len * 5) / 8;
        for (size_t lp = 0; lp < d_len; lp++) {
            fprintf(stderr, "%c", p_data[lp]);
        }
        break;
    case 6:
        //expiry second
        {
            uint64_t expiry = convert_32(p_tag, len);
            fprintf(stderr, "invoice expiry=%" PRIu32 "\n", (uint32_t)expiry);
        }
        break;
    case 24:
        //min_final_cltv_expiry
        {
            p_invoice_data->min_final_cltv_expiry = convert_32(p_tag, len);

        }
        break;
    case 3:
        //extra routing info
        if (!convert_bits(p_data, &d_len, 8, p_tag, len, 5, true)) return false;
        d_len =  (len * 5) / 8;
        if (d_len < 102) return false;

        {
            const uint8_t *p = p_data;

            for (int lp2 = 0; lp2 < d_len / 51; lp2++) {
                fprintf(stderr, "-----------\npubkey= ");
                for (size_t lp = 0; lp < 33; lp++) {
                    fprintf(stderr, "%02x", *p++);
                }
                fprintf(stderr, "\n");

                uint64_t short_channel_id = 0;
                for (size_t lp = 0; lp < sizeof(uint64_t); lp++) {
                    short_channel_id <<= 8;
                    short_channel_id |= *p++;
                }
                fprintf(stderr, "short_channel_id= %016" PRIx64 "\n", short_channel_id);

                uint32_t fee_base_msat = 0;
                for (size_t lp = 0; lp < sizeof(uint32_t); lp++) {
                    fee_base_msat <<= 8;
                    fee_base_msat |= *p++;
                }
                fprintf(stderr, "fee_base_msat= %d\n", fee_base_msat);

                uint32_t fee_proportional_millionths = 0;
                for (size_t lp = 0; lp < sizeof(uint32_t); lp++) {
                    fee_proportional_millionths <<= 8;
                    fee_proportional_millionths |= *p++;
                }
                fprintf(stderr, "fee_proportional_millionths= %d\n", fee_proportional_millionths);

                uint16_t cltv_expiry_delta = 0;
                for (size_t lp = 0; lp < sizeof(uint16_t); lp++) {
                    cltv_expiry_delta <<= 8;
                    cltv_expiry_delta |= *p++;
                }
                fprintf(stderr, "cltv_expiry_delta= %d\n", cltv_expiry_delta);
            }
        }
        break;
    default:
        if (!convert_bits(p_data, &d_len, 8, p_tag, len, 5, true)) return false;
        d_len =  (len * 5) / 8;
        if (tag == 1) {
            memcpy(p_invoice_data->payment_hash, p_data, UCOIN_SZ_SHA256);
        }
        for (size_t lp = 0; lp < d_len; lp++) {
            fprintf(stderr, "%02x", p_data[lp]);
        }
    }
    fprintf(stderr, "\n\n");
    free(p_data);

    *p_len = 3 + len;
    return true;
}

bool segwit_addr_encode(char *output, uint8_t hrp_type, int witver, const uint8_t *witprog, size_t witprog_len) {
    uint8_t data[65];
    size_t datalen = 0;
    if (witver > 16) return false;
    if (witver == 0 && witprog_len != 20 && witprog_len != 32) return false;
    if (witprog_len < 2 || witprog_len > 40) return false;
    if ((hrp_type != SEGWIT_ADDR_MAINNET) && (hrp_type != SEGWIT_ADDR_TESTNET)) return false;
    data[0] = witver;
    if (!convert_bits(data + 1, &datalen, 5, witprog, witprog_len, 8, true)) return false;
    ++datalen;
    return bech32_encode(output, hrp_str[hrp_type], k_chk[hrp_type], data, datalen);
}

bool segwit_addr_decode(int* witver, uint8_t* witdata, size_t* witdata_len, uint8_t hrp_type, const char* addr) {
    uint8_t data[84];
    char hrp_actual[84];
    size_t data_len;
    if ((hrp_type != SEGWIT_ADDR_MAINNET) && (hrp_type != SEGWIT_ADDR_TESTNET)) return false;
    if (!bech32_decode(hrp_actual, data, &data_len, addr, false)) return false;
    if (data_len == 0 || data_len > 65) return false;
    if (strncmp(hrp_str[hrp_type], hrp_actual, 2) != 0) return false;
    if (data[0] > 16) return false;
    *witdata_len = 0;
    if (!convert_bits(witdata, witdata_len, 8, data + 1, data_len - 1, 5, false)) return false;
    if (*witdata_len < 2 || *witdata_len > 40) return false;
    if (data[0] == 0 && *witdata_len != 20 && *witdata_len != 32) return false;
    *witver = data[0];
    return true;
}

#if 0
bool ln_invoice_encode(char *output, uint8_t hrp_type, uint64_t Amount, const uint8_t *pPayHash, const uint8_t *pPrivKey) {
    uint8_t data[1024];
    size_t datalen = 0;
    if ((hrp_type != LN_INVOICE_MAINNET) && (hrp_type != LN_INVOICE_TESTNET)) return false;

    //timestamp
    time_t now = time(NULL);
    uint8_t tmval[4];
    tmval[0] = (now >> 24) & 0xff;
    tmval[1] = (now >> 16) & 0xff;
    tmval[2] = (now >>  8) & 0xff;
    tmval[3] = now & 0xff;
    if (!convert_bits(data, &datalen, 5, tmval, sizeof(tmval), 8, true)) return false;

    //tagged field(payee pubkey)
    uint8_t pubkey[UCOIN_SZ_PUBKEY];
    ucoin_keys_priv2pub(pubkey, pPrivKey);
    data[datalen++] = 'n';
    data[datalen++] = 'p';
    data[datalen++] = 'z';
    if (!convert_bits(data + datalen, &datalen, 5, pubkey, sizeof(pubkey), 8, true)) return false;

    //tagged field(payment_hash)
    data[datalen++] = 'n';
    data[datalen++] = 'p';
    data[datalen++] = 'q';
    if (!convert_bits(data, &datalen, 5, pPayHash, UCOIN_SZ_SHA256, 8, true)) return false;

    //signature
    uint8_t hash[UCOIN_SZ_SHA256];
    mbedtls_sha256(data, datalen, hash, 0);
    uint8_t sign[UCOIN_SZ_SIGN_RS];
    bool ret = ucoin_tx_sign_rs(sign, hash, pPrivKey);
    if (!convert_bits(data, &datalen, 5, sign, sizoef(sign), 8, true)) return false;

    //revocation ID
    //  timestamp(4) +
    ++datalen;
    return bech32_encode(output, hrp_str[hrp_type], k_chk[hrp_type], data, datalen);
}
#endif

bool ln_invoice_decode(ln_invoice_t *p_invoice_data, const char* invoice) {
    bool ret;
    uint8_t data[1024];
    char hrp_actual[84];
    size_t data_len;
    if (!bech32_decode(hrp_actual, data, &data_len, invoice, true)) return false;
    if (strncmp(hrp_str[LN_INVOICE_MAINNET], hrp_actual, 4) == 0) {
        p_invoice_data->hrp_type = LN_INVOICE_MAINNET;
    } else if (strncmp(hrp_str[LN_INVOICE_TESTNET], hrp_actual, 4) == 0) {
        p_invoice_data->hrp_type = LN_INVOICE_TESTNET;
    } else {
        return false;
    }
    size_t amt_len = strlen(hrp_actual) - 4;
    if (amt_len > 0) {
        char amount_str[20];

        if ((hrp_actual[4] < '1') || ('9' < hrp_actual[4])) return false;
        for (size_t lp = 1; lp < amt_len - 1; lp++) {
            if (!isdigit(hrp_actual[4 + lp])) return false;
        }
        memcpy(amount_str, hrp_actual + 4, amt_len - 1);
        amount_str[amt_len - 1] = '\0';
        char *endptr = NULL;
        uint64_t amount_msat = (uint64_t)strtoull(amount_str, &endptr, 10);
        switch (hrp_actual[4 + amt_len - 1]) {
            case 'm': amount_msat *= (uint64_t)100000000; break;
            case 'u': amount_msat *= (uint64_t)100000; break;
            case 'n': amount_msat *= (uint64_t)100; break;
            case 'p': amount_msat = (uint64_t)(amount_msat * 0.1); break;
            default: return false;
        };
        p_invoice_data->amount_msat = amount_msat;
    } else {
        p_invoice_data->amount_msat = 0;
    }

    /*
     * +-------------------+
     * | "lnbc" or "lntb"  |
     * | (amount)          |
     * +-------------------+
     * | timestamp         |
     * | (tagged fields)   |
     * | signature         |
     * | recovery ID       |
     * | checksum          |
     * +-------------------+
     */
    const uint8_t *p_tag = data + 7;
    const uint8_t *p_sig = data + data_len - 104;

    p_invoice_data->min_final_cltv_expiry = LN_MIN_FINAL_CLTV_EXPIRY;

    //preimage
    uint8_t *pdata = (uint8_t *)malloc(((data_len - 104) * 5 + 7) / 8);
    size_t pdata_len = 0;
    if (!convert_bits(pdata, &pdata_len, 8, data, data_len - 104, 5, true)) return false;
    size_t len_hrp = strlen(hrp_actual);
    size_t total_len = len_hrp + pdata_len;
    uint8_t *preimg = (uint8_t *)malloc(total_len);
    memcpy(preimg, hrp_actual, len_hrp);
    memcpy(preimg + len_hrp, pdata, pdata_len);
    free(pdata);

    //hash
    uint8_t hash[UCOIN_SZ_SHA256];
    mbedtls_sha256((uint8_t *)preimg, total_len, hash, 0);
    free(preimg);

    //signature(104 chars)
    uint8_t sig[65];
    size_t sig_len = 0;
    if (!convert_bits(sig, &sig_len, 8, p_sig, 104, 5, false)) return false;
    //fprintf(stderr, "sig= ");
    //for (int lp = 0; lp < UCOIN_SZ_SIGN_RS; lp++) {
    //    fprintf(stderr, "%02x", sig[lp]);
    //}
    //fprintf(stderr, "\n");
    //fprintf(stderr, "recovery ID=%02x\n", sig[UCOIN_SZ_SIGN_RS]);
    ret = ucoin_tx_recover_pubkey(p_invoice_data->pubkey, sig[UCOIN_SZ_SIGN_RS], sig, hash);
    if (ret) {
        //fprintf(stderr, "recovery pubkey= ");
        //for (int lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
        //    fprintf(stderr, "%02x", p_invoice_data->pubkey[lp]);
        //}
        //fprintf(stderr, "\n");
    } else {
        fprintf(stderr, "fail: recovery pubkey\n");
    }

    //timestamp(7 chars)
    time_t tm = (time_t)convert_be64(data, 7);
    p_invoice_data->timestamp = (uint64_t)tm;
    //fprintf(stderr, "timestamp= %" PRIu64 " : %s", (uint64_t)tm, ctime(&tm));

    //tagged fields
    //fprintf(stderr, "data_len=%d\n", (int)data_len);
    ret = true;
    while (p_tag < p_sig) {
        size_t len;
        ret = analyze_tag(&len, p_tag, p_invoice_data);
        if (!ret) {
            break;
        }
        p_tag += len;
    }

    return ret;
}
