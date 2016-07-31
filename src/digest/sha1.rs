// Copyright 2015-2016 Brian Smith.
// Copyright 2016 Simon Sapin.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use {c, polyfill};
use super::MAX_CHAINING_LEN;

pub const BLOCK_LEN: usize = 512 / 8;
pub const CHAINING_LEN: usize = 160 / 8;
const CHAINING_WORDS: usize = CHAINING_LEN / 4;

#[inline] fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) | (!x & z) }
#[inline] fn parity(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }
#[inline] fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) | (x & z) | (y & z) }

/// The main purpose in retaining this is to support legacy protocols and OCSP,
/// none of which need a fast SHA-1 implementation.
/// This implementation therefore favors size and simplicity over speed.
/// Unlike SHA-256, SHA-384, and SHA-512,
/// there is no assembly language implementation.
pub fn block_data_order(state: &mut [u64; MAX_CHAINING_LEN / 8],
                             data: &[u8],
                             num: c::size_t) {
    let state = polyfill::slice::u64_as_u32_mut(state);
    let state = &mut state[..CHAINING_WORDS];
    let state = slice_as_array_ref_mut!(state, CHAINING_WORDS).unwrap();

    let mut w: [u32; 80] = [0; 80];
    for i in 0..num {
        let block = &data[i * BLOCK_LEN..][..BLOCK_LEN];
        for t in 0..16 {
            let word = slice_as_array_ref!(&block[t * 4..][..4], 4).unwrap();
            w[t] = polyfill::slice::u32_from_be_u8(word);
        }
        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];

        for t in 0..80 {
            let (k, f) = match t {
                0...19 => (0x5a827999, ch(b, c, d)),
                20...39 => (0x6ed9eba1, parity(b, c, d)),
                40...59 => (0x8f1bbcdc, maj(b, c, d)),
                60...79 => (0xca62c1d6, parity(b, c, d)),
                _ => unreachable!()
            };
            let tt = a.rotate_left(5)
                      .wrapping_add(f)
                      .wrapping_add(e)
                      .wrapping_add(k)
                      .wrapping_add(w[t]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tt;
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
}
