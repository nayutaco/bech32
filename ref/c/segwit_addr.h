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

#ifndef _SEGWIT_ADDR_H_
#define _SEGWIT_ADDR_H_ 1

#include <stdint.h>
#include <stdbool.h>

#define SEGWIT_ADDR_MAINNET     ((uint8_t)0)
#define SEGWIT_ADDR_TESTNET     ((uint8_t)1)
#define LN_INVOICE_MAINNET      ((uint8_t)2)
#define LN_INVOICE_TESTNET      ((uint8_t)3)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/** Encode a SegWit address
 *
 *  Out: output:   Pointer to a buffer of size 73 + strlen(hrp) that will be
 *                 updated to contain the null-terminated address.
 *  In:  hrp_type: SEGWIT_ADDR_MAINNET or SEGWIT_ADDR_TESTNET
 *       ver:      Version of the witness program (between 0 and 16 inclusive).
 *       prog:     Data bytes for the witness program (between 2 and 40 bytes).
 *       prog_len: Number of data bytes in prog.
 *  Returns true if successful.
 */
bool segwit_addr_encode(
    char *output,
    uint8_t hrp_type,
    int ver,
    const uint8_t *prog,
    size_t prog_len
);

/** Decode a SegWit address
 *
 *  Out: ver:      Pointer to an int that will be updated to contain the witness
 *                 program version (between 0 and 16 inclusive).
 *       prog:     Pointer to a buffer of size 40 that will be updated to
 *                 contain the witness program bytes.
 *       prog_len: Pointer to a size_t that will be updated to contain the length
 *                 of bytes in prog.
 *       hrp_type: SEGWIT_ADDR_MAINNET or SEGWIT_ADDR_TESTNET
 *       addr:     Pointer to the null-terminated address.
 *  Returns true if successful.
 */
bool segwit_addr_decode(
    int* ver,
    uint8_t* prog,
    size_t* prog_len,
    uint8_t hrp_type,
    const char* addr
);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif
