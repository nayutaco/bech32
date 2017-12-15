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
#include <inttypes.h>
#include <time.h>
#include <assert.h>

#include "mbedtls/sha256.h"

#include "ucoin.h"
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

static bool analyze_tag(size_t *p_len, const uint8_t *p_tag)
{
    printf("------------------\n");
    uint8_t tag = *p_tag;
    switch (tag) {
    case 1:
        printf("payment_hash\n");
        break;
    case 13:
        printf("purpose of payment(ASCII)\n");
        break;
    case 19:
        printf("pubkey of payee node\n");
        break;
    case 23:
        printf("purpose of payment(SHA256)\n");
        break;
    case 6:
        printf("expiry second\n");
        break;
    case 24:
        printf("min_final_cltv_expiry\n");
        break;
    case 9:
        printf("Fallback on-chain\n");
        break;
    case 3:
        printf("extra routing info\n");
        break;
    default:
        printf("unknown tag: %02x\n", *p_tag);
        break;
    }
    int len = p_tag[1] * 0x20 + p_tag[2];
    printf("  len=%d\n", len);
    p_tag += 3;
    uint8_t *p_data = (uint8_t *)malloc((len * 5 + 7) / 8); //確保サイズは切り上げ
    size_t d_len = 0;
    switch (tag) {
    case 13:
        //purpose of payment(ASCII)
        if (!convert_bits(p_data, &d_len, 8, p_tag, len, 5, true)) return false;
        d_len =  (len * 5) / 8;
        for (size_t lp = 0; lp < d_len; lp++) {
            printf("%c", p_data[lp]);
        }
        break;
    case 6:
        //expiry second
        {
            uint64_t expiry = convert_32(p_tag, len);
            printf("expiry=%" PRIu32 "\n", (uint32_t)expiry);
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
                printf("-----------\npubkey= ");
                for (size_t lp = 0; lp < 33; lp++) {
                    printf("%02x", *p++);
                }
                printf("\n");

                uint64_t short_channel_id = 0;
                for (size_t lp = 0; lp < sizeof(uint64_t); lp++) {
                    short_channel_id <<= 8;
                    short_channel_id |= *p++;
                }
                printf("short_channel_id= %016" PRIx64 "\n", short_channel_id);

                uint32_t fee_base_msat = 0;
                for (size_t lp = 0; lp < sizeof(uint32_t); lp++) {
                    fee_base_msat <<= 8;
                    fee_base_msat |= *p++;
                }
                printf("fee_base_msat= %d\n", fee_base_msat);

                uint32_t fee_proportional_millionths = 0;
                for (size_t lp = 0; lp < sizeof(uint32_t); lp++) {
                    fee_proportional_millionths <<= 8;
                    fee_proportional_millionths |= *p++;
                }
                printf("fee_proportional_millionths= %d\n", fee_proportional_millionths);

                uint16_t cltv_expiry_delta = 0;
                for (size_t lp = 0; lp < sizeof(uint16_t); lp++) {
                    cltv_expiry_delta <<= 8;
                    cltv_expiry_delta |= *p++;
                }
                printf("cltv_expiry_delta= %d\n", cltv_expiry_delta);
            }
        }
        break;
    default:
        if (!convert_bits(p_data, &d_len, 8, p_tag, len, 5, true)) return false;
        d_len =  (len * 5) / 8;
        for (size_t lp = 0; lp < d_len; lp++) {
            printf("%02x", p_data[lp]);
        }
    }
    printf("\n\n");
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

bool ln_invoice_encode(char *output, uint8_t hrp_type, int witver, const uint8_t *witprog, size_t witprog_len) {
    uint8_t data[65];
    size_t datalen = 0;
    if (witver > 16) return false;
    if (witver == 0 && witprog_len != 20 && witprog_len != 32) return false;
    if (witprog_len < 2 || witprog_len > 40) return false;
    if ((hrp_type != LN_INVOICE_MAINNET) && (hrp_type != LN_INVOICE_TESTNET)) return false;
    data[0] = witver;
    if (!convert_bits(data + 1, &datalen, 5, witprog, witprog_len, 8, true)) return false;
    ++datalen;
    return bech32_encode(output, hrp_str[hrp_type], k_chk[hrp_type], data, datalen);
}

bool ln_invoice_decode(uint8_t* ivcdata, size_t* ivcdata_len, uint8_t hrp_type, const char* invoice) {
    uint8_t data[584];
    char hrp_actual[84];
    size_t data_len;
    if ((hrp_type != LN_INVOICE_MAINNET) && (hrp_type != LN_INVOICE_TESTNET)) return false;
    if (!bech32_decode(hrp_actual, data, &data_len, invoice, true)) return false;
    if (strncmp(hrp_str[hrp_type], hrp_actual, 4) != 0) return false;
    size_t amt_len = strlen(hrp_actual) - 4;
    if (amt_len > 0) {
        printf("amount= ");
        for (size_t lp = 0; lp < amt_len; lp++) {
            printf("%c", hrp_actual[4 + lp]);
        }
        printf("\n");
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

uint8_t *pdata = (uint8_t *)malloc(((data_len - 104) * 5 + 7) / 8);
size_t pdata_len = 0;
if (!convert_bits(pdata, &pdata_len, 8, data, data_len - 104, 5, true)) { printf("fail\n"); return false;}

size_t total_len = (strlen(hrp_actual) + pdata_len) * 2;
char *pdata_str = (char *)malloc(total_len + 1);
pdata_str[0] = '\0';
for (int lp = 0; lp < strlen(hrp_actual); lp++) {
    char str[3];
    sprintf(str, "%02x", hrp_actual[lp]);
    strcat(pdata_str, str);
}
for (int lp = 0; lp < pdata_len; lp++) {
    char str[3];
    sprintf(str, "%02x", pdata[lp]);
    strcat(pdata_str, str);
}
free(pdata);
printf("pdata= %s\n", pdata_str);

    //hash
    uint8_t hash[UCOIN_SZ_SHA256];
//    uint8_t *p = (uint8_t *)malloc(strlen(hrp_actual) + data_len - 104);
    mbedtls_sha256((uint8_t *)pdata_str, total_len, hash, 0);
printf("hash= ");
for (int lp = 0; lp < UCOIN_SZ_SHA256; lp++) {
    printf("%02x", hash[lp]);
}
printf("\n\n");

    const uint8_t priv[] = {
        0xe1, 0x26, 0xf6, 0x8f, 0x7e, 0xaf, 0xcc, 0x8b,
        0x74, 0xf5, 0x4d, 0x26, 0x9f, 0xe2, 0x06, 0xbe,
        0x71, 0x50, 0x00, 0xf9, 0x4d, 0xac, 0x06, 0x7d,
        0x1c, 0x04, 0xa8, 0xca, 0x3b, 0x2d, 0xb7, 0x34,
    };
    uint8_t sig_rs[UCOIN_SZ_SIGN_RS];
    bool b = ucoin_tx_sign_rs(sig_rs, hash, priv);
    assert(b);
printf("sig= ");
for (int lp = 0; lp < UCOIN_SZ_SIGN_RS; lp++) {
    printf("%02x", sig_rs[lp]);
}
printf("\n\n");

    //signature(104 chars)
    uint8_t sig[65];
    size_t sig_len = 0;
    if (!convert_bits(sig, &sig_len, 8, p_sig, 104, 5, false)) return false;
printf("sig_len=%d\n", (int)sig_len);
for (int lp = 0; lp < UCOIN_SZ_SIGN_RS; lp++) {
    printf("%02x", sig[lp]);
}
printf("\n");
printf("recovery ID=%02x\n", sig[UCOIN_SZ_SIGN_RS]);
printf("\n\n");

    //timestamp(7 chars)
    time_t tm = (time_t)convert_be64(data, 7);
    printf("timestamp= %" PRIu64 " : %s", (uint64_t)tm, ctime(&tm));

    //tagged fields
    printf("data_len=%d\n", (int)data_len);
    bool ret = true;
    while (p_tag < p_sig) {
        size_t len;
        ret = analyze_tag(&len, p_tag);
        if (!ret) {
            break;
        }
        p_tag += len;
    }

    return ret;
}
