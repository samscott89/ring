// Copyright 2015-2016 Brian Smith.
// Copyright 2016 Simon Sapin.
// Copyright 2016 Sam Scott.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use c;
use core;
use polyfill;

use super::MAX_CHAINING_LEN;

// SHA-256: 512-bit blocks
const BLOCK_LEN_256: usize = 512/8;

// SHA-384, SHA-512: 1024-bit blocks
const BLOCK_LEN_512: usize = 1024/8;

// SHA-256: State is 256 bits
pub const CHAINING_LEN_256: usize = 256 / 8;
// SHA-384, SHA-512: State is 512 bits
pub const CHAINING_LEN_512: usize = 512 / 8;

// State as number of words
const CHAINING_WORDS_256: usize = CHAINING_LEN_256 / 4;
const CHAINING_WORDS_512: usize = CHAINING_LEN_512 / 8;

macro_rules! ch {
    ($x:ident, $y:ident, $z:ident) => (($x & $y) ^ (!$x & $z))
}
macro_rules! parity {
    ($x:ident, $y:ident, $z:ident) => ($x ^ $y ^ $z)
}
macro_rules! maj {
    ($x:ident, $y:ident, $z:ident) => (($x & $y) ^ ($x & $z) ^ ($y & $z))
}

// SHA-256 functions
#[inline] fn big_s0_256(x: u32) -> u32   { ((x.rotate_right(9)  ^ x).rotate_right(11) ^ x).rotate_right(2) }
#[inline] fn big_s1_256(x: u32) -> u32   { ((x.rotate_right(14) ^ x).rotate_right(5)  ^ x).rotate_right(6) }
#[inline] fn small_s0_256(x: u32) -> u32 { x.rotate_right(7)  ^ x.rotate_right(18) ^ (x >> 3) }
#[inline] fn small_s1_256(x: u32) -> u32 { x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10) }

// SHA-512 functions
#[inline] fn big_s0_512(x: u64) -> u64   { ((x.rotate_right(5)  ^ x).rotate_right(6) ^ x).rotate_right(28) }
#[inline] fn big_s1_512(x: u64) -> u64   { ((x.rotate_right(23) ^ x).rotate_right(4) ^ x).rotate_right(14) }
#[inline] fn small_s0_512(x: u64) -> u64 { x.rotate_right(1)  ^ x.rotate_right(8)  ^ (x >> 7) }
#[inline] fn small_s1_512(x: u64) -> u64 { x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6) }

pub unsafe extern fn sha256_block_data_order(state: &mut [u64; MAX_CHAINING_LEN / 8],
                                             data: *const u8,
                                             num: c::size_t) {
    let data = data as *const [u8; BLOCK_LEN_256];
    let blocks = core::slice::from_raw_parts(data, num);
    sha256_block_data_order_safe(state, blocks)
}

// SHA-256 message scheduling. Four iterations in one.
macro_rules! msched_256 {
    ($x0:ident,$x1:ident,$x2:ident,$x3:ident,$xt:ident) => {
      $xt[0] = small_s0_256($x0[1])
            .wrapping_add($x0[0])
            .wrapping_add($x2[1])
            .wrapping_add(small_s1_256($x3[2]));

      $xt[1] = small_s0_256($x0[2])
            .wrapping_add($x0[1])
            .wrapping_add($x2[2])
            .wrapping_add(small_s1_256($x3[3]));

      $xt[2] = small_s0_256($x0[3])
            .wrapping_add($x0[2])
            .wrapping_add($x2[3])
            .wrapping_add(small_s1_256($xt[0]));

      $xt[3] = small_s0_256($x1[0])
            .wrapping_add($x0[3])
            .wrapping_add($x3[0])
            .wrapping_add(small_s1_256($xt[1]));
    }
}

// SHA-512 message scheduling. Four iterations in one.
macro_rules! msched_512 {
    ($x0:ident,$x1:ident,$x2:ident,$x3:ident,$xt:ident) => (
      $xt[0] = small_s1_512($x3[2])
            .wrapping_add($x2[1])
            .wrapping_add(small_s0_512($x0[1]))
            .wrapping_add($x0[0]);

      $xt[1] = small_s1_512($x3[3])
            .wrapping_add($x2[2])
            .wrapping_add(small_s0_512($x0[2]))
            .wrapping_add($x0[1]);

      $xt[2] = small_s1_512($xt[0])
            .wrapping_add($x2[3])
            .wrapping_add(small_s0_512($x0[3]))
            .wrapping_add($x0[2]);

      $xt[3] = small_s1_512($xt[1])
            .wrapping_add($x3[0])
            .wrapping_add(small_s0_512($x1[0]))
            .wrapping_add($x0[3]);
    )
}

// SHA-256 round functions.
macro_rules! round_256 {
    ($i:expr,$ti:expr,$x:ident,$a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident) => {{
          let t1 = $h.wrapping_add(big_s1_256($e))
                    .wrapping_add(ch!($e, $f, $g))
                    .wrapping_add(K_256[$ti])
                    .wrapping_add($x[$i]);
          let t2 = big_s0_256($a).wrapping_add(maj!($a,$b,$c));
          $h = $g;
          $g = $f;
          $f = $e;
          $e = $d.wrapping_add(t1);
          $d = $c;
          $c = $b;
          $b = $a;
          $a = t1.wrapping_add(t2);
        }}
}

// SHA-256 round functions, four iterations.
macro_rules! round_256_x4 {
    ($t:expr,$w:ident,$a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident) => {{
          let x = $w[$t];
          round_256!(0,4*$t+0, x, $a,$b,$c,$d,$e,$f,$g,$h);
          round_256!(1,4*$t+1, x, $a,$b,$c,$d,$e,$f,$g,$h);
          round_256!(2,4*$t+2, x, $a,$b,$c,$d,$e,$f,$g,$h);
          round_256!(3,4*$t+3, x, $a,$b,$c,$d,$e,$f,$g,$h);
        }}
}

// SHA-512 round functions.
macro_rules! round_512 {
    ($i:expr,$ti:expr,$x:ident,$a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident) => {{
          let t1 = $h.wrapping_add(big_s1_512($e))
                    .wrapping_add(ch!($e, $f, $g))
                    .wrapping_add(K_512[$ti])
                    .wrapping_add($x[$i]);
          let t2 = big_s0_512($a).wrapping_add(maj!($a,$b,$c));
          $h = $g;
          $g = $f;
          $f = $e;
          $e = $d.wrapping_add(t1);
          $d = $c;
          $c = $b;
          $b = $a;
          $a = t1.wrapping_add(t2);
        }}
}

// SHA-512 round functions, four iterations.
macro_rules! round_512_x4 {
    ($t:expr,$w:ident,$a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident) => {{
          let x = $w[$t];
          round_512!(0,4*$t+0, x, $a,$b,$c,$d,$e,$f,$g,$h);
          round_512!(1,4*$t+1, x, $a,$b,$c,$d,$e,$f,$g,$h);
          round_512!(2,4*$t+2, x, $a,$b,$c,$d,$e,$f,$g,$h);
          round_512!(3,4*$t+3, x, $a,$b,$c,$d,$e,$f,$g,$h);
        }}
}

fn sha256_block_data_order_safe(state: &mut [u64; MAX_CHAINING_LEN / 8],
                                blocks: &[[u8; BLOCK_LEN_256]]) {

    // Convert state to array of u32
    let state = polyfill::slice::u64_as_u32_mut(state);
    let state = &mut state[..CHAINING_WORDS_256];
    let state = slice_as_array_ref_mut!(state, CHAINING_WORDS_256).unwrap();

    // Message schedule
    for block in blocks {
        let mut w: [[u32; 4]; 16] = [[0; 4]; 16];

        for t in 0..4 {
            for i in 0..4 {
                let word = slice_as_array_ref!(&block[(4*t + i) * 4..][..4], 4).unwrap();
                w[t][i] = polyfill::slice::u32_from_be_u8(word); 
            }
        }

        let mut x0 = w[0]; // w[t-16], w[t-15], w[t-14], w[t-13]
        let mut x1 = w[1]; // w[t-12], w[t-11], w[t-10], w[t-9]
        let mut x2 = w[2]; // w[t-8],  w[t-7],  w[t-6],  w[t-5]
        let mut x3 = w[3]; // w[t-4],  w[t-3],  w[t-2],  w[t-1]
        let mut xt = w[4];
        msched_256!(x0, x1, x2, x3, xt);
        w[4] = xt;
        x0 = w[5];
        msched_256!(x1, x2, x3, xt, x0);
        w[5] = x0;
        x1 = w[6];
        msched_256!(x2, x3, xt, x0, x1);
        w[6] = x1;
        x2 = w[7];
        msched_256!(x3, xt, x0, x1, x2);
        w[7] = x2;
        x3 = w[8];
        msched_256!(xt, x0, x1, x2, x3);
        w[8] = x3;
        xt = w[9];
        msched_256!(x0, x1, x2, x3, xt);
        w[9] = xt;
        x0 = w[10];
        msched_256!(x1, x2, x3, xt, x0);
        w[10] = x0;
        x1 = w[11];
        msched_256!(x2, x3, xt, x0, x1);
        w[11] = x1;
        x2 = w[12];
        msched_256!(x3, xt, x0, x1, x2);
        w[12] = x2;
        x3 = w[13];
        msched_256!(xt, x0, x1, x2, x3);
        w[13] = x3;
        xt = w[14];
        msched_256!(x0, x1, x2, x3, xt);
        w[14] = xt;
        x0 = w[15];
        msched_256!(x1, x2, x3, xt, x0);
        w[15] = x0;

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        round_256_x4!(0, w, a,b,c,d,e,f,g,h);
        round_256_x4!(1, w, a,b,c,d,e,f,g,h);
        round_256_x4!(2, w, a,b,c,d,e,f,g,h);
        round_256_x4!(3, w, a,b,c,d,e,f,g,h);
        round_256_x4!(4, w, a,b,c,d,e,f,g,h);
        round_256_x4!(5, w, a,b,c,d,e,f,g,h);
        round_256_x4!(6, w, a,b,c,d,e,f,g,h);
        round_256_x4!(7, w, a,b,c,d,e,f,g,h);
        round_256_x4!(8, w, a,b,c,d,e,f,g,h);
        round_256_x4!(9, w, a,b,c,d,e,f,g,h);
        round_256_x4!(10, w, a,b,c,d,e,f,g,h);
        round_256_x4!(11, w, a,b,c,d,e,f,g,h);
        round_256_x4!(12, w, a,b,c,d,e,f,g,h);
        round_256_x4!(13, w, a,b,c,d,e,f,g,h);
        round_256_x4!(14, w, a,b,c,d,e,f,g,h);
        round_256_x4!(15, w, a,b,c,d,e,f,g,h);

        state[0] = a.wrapping_add(state[0]);
        state[1] = b.wrapping_add(state[1]);
        state[2] = c.wrapping_add(state[2]);
        state[3] = d.wrapping_add(state[3]);
        state[4] = e.wrapping_add(state[4]);
        state[5] = f.wrapping_add(state[5]);
        state[6] = g.wrapping_add(state[6]);
        state[7] = h.wrapping_add(state[7]);
    }
}

pub unsafe extern fn sha512_block_data_order(state: &mut [u64; MAX_CHAINING_LEN / 8],
                                             data: *const u8,
                                             num: c::size_t) {
    let data = data as *const [u8; BLOCK_LEN_512];
    let blocks = core::slice::from_raw_parts(data, num);
    sha512_block_data_order_safe(state, blocks)
}

fn sha512_block_data_order_safe(state: &mut [u64; MAX_CHAINING_LEN / 8],
                                blocks: &[[u8; BLOCK_LEN_512]]) {

    // Convert state to array of Wrapping<64>
    let state = &mut state[..CHAINING_WORDS_512];
    let state = slice_as_array_ref_mut!(state, CHAINING_WORDS_512).unwrap();

    // Message schedule Wt
    let mut w: [[u64; 4]; 20] = [[0; 4]; 20];

    for block in blocks {
        for t in 0..4 {
            for i in 0..4 {
                let word = slice_as_array_ref!(&block[(4*t + i) * 8..][..8], 8).unwrap();
                w[t][i] = polyfill::slice::u64_from_be_u8(word);
            }
        }

        let mut x0 = w[0]; // w[t-16], w[t-15], w[t-14], w[t-13]
        let mut x1 = w[1]; // w[t-12], w[t-11], w[t-10], w[t-9]
        let mut x2 = w[2]; // w[t-8],  w[t-7],  w[t-6],  w[t-5]
        let mut x3 = w[3]; // w[t-4],  w[t-3],  w[t-2],  w[t-1]
        let mut xt = w[4];
        msched_512!(x0, x1, x2, x3, xt);
        w[4] = xt;
        x0 = w[5];
        msched_512!(x1, x2, x3, xt, x0);
        w[5] = x0;
        x1 = w[6];
        msched_512!(x2, x3, xt, x0, x1);
        w[6] = x1;
        x2 = w[7];
        msched_512!(x3, xt, x0, x1, x2);
        w[7] = x2;
        x3 = w[8];
        msched_512!(xt, x0, x1, x2, x3);
        w[8] = x3;
        xt = w[9];
        msched_512!(x0, x1, x2, x3, xt);
        w[9] = xt;
        x0 = w[10];
        msched_512!(x1, x2, x3, xt, x0);
        w[10] = x0;
        x1 = w[11];
        msched_512!(x2, x3, xt, x0, x1);
        w[11] = x1;
        x2 = w[12];
        msched_512!(x3, xt, x0, x1, x2);
        w[12] = x2;
        x3 = w[13];
        msched_512!(xt, x0, x1, x2, x3);
        w[13] = x3;
        xt = w[14];
        msched_512!(x0, x1, x2, x3, xt);
        w[14] = xt;
        x0 = w[15];
        msched_512!(x1, x2, x3, xt, x0);
        w[15] = x0;
        x1 = w[16];
        msched_512!(x2, x3, xt, x0, x1);
        w[16] = x1;
        x2 = w[17];
        msched_512!(x3, xt, x0, x1, x2);
        w[17] = x2;
        x3 = w[18];
        msched_512!(xt, x0, x1, x2, x3);
        w[18] = x3;
        xt = w[19];
        msched_512!(x0, x1, x2, x3, xt);
        w[19] = xt;

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        round_512_x4!(0, w, a,b,c,d,e,f,g,h);
        round_512_x4!(1, w, a,b,c,d,e,f,g,h);
        round_512_x4!(2, w, a,b,c,d,e,f,g,h);
        round_512_x4!(3, w, a,b,c,d,e,f,g,h);
        round_512_x4!(4, w, a,b,c,d,e,f,g,h);
        round_512_x4!(5, w, a,b,c,d,e,f,g,h);
        round_512_x4!(6, w, a,b,c,d,e,f,g,h);
        round_512_x4!(7, w, a,b,c,d,e,f,g,h);
        round_512_x4!(8, w, a,b,c,d,e,f,g,h);
        round_512_x4!(9, w, a,b,c,d,e,f,g,h);
        round_512_x4!(10, w, a,b,c,d,e,f,g,h);
        round_512_x4!(11, w, a,b,c,d,e,f,g,h);
        round_512_x4!(12, w, a,b,c,d,e,f,g,h);
        round_512_x4!(13, w, a,b,c,d,e,f,g,h);
        round_512_x4!(14, w, a,b,c,d,e,f,g,h);
        round_512_x4!(15, w, a,b,c,d,e,f,g,h);
        round_512_x4!(16, w, a,b,c,d,e,f,g,h);
        round_512_x4!(17, w, a,b,c,d,e,f,g,h);
        round_512_x4!(18, w, a,b,c,d,e,f,g,h);
        round_512_x4!(19, w, a,b,c,d,e,f,g,h);

        state[0] = a.wrapping_add(state[0]);
        state[1] = b.wrapping_add(state[1]);
        state[2] = c.wrapping_add(state[2]);
        state[3] = d.wrapping_add(state[3]);
        state[4] = e.wrapping_add(state[4]);
        state[5] = f.wrapping_add(state[5]);
        state[6] = g.wrapping_add(state[6]);
        state[7] = h.wrapping_add(state[7]);
    }
}

// SHA-256 constants K
const K_256: [u32; 64] = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
    0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
    0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
    0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

// SHA-512 constants K
const K_512: [u64; 80] = [0x428a2f98d728ae22, 0x7137449123ef65cd,
      0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
      0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
      0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c,
      0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
      0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2,
      0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
      0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4,
      0x76f988da831153b5, 0x983e5152ee66dfab, 0xa831c66d2db43210,
      0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2,
      0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
      0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
      0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8,
      0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364,
      0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
      0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a,
      0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
      0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63,
      0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
      0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72,
      0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9,
      0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
      0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
      0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae,
      0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493,
      0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6,
      0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817];
