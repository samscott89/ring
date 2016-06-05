use c;
use core;
use polyfill;
use super::MAX_CHAINING_LEN;

pub const CHAINING_LEN: usize = 256 / 8;
pub const BLOCK_LEN: usize = 512 / 8;
const CHAINING_WORDS: usize = CHAINING_LEN / 4;

pub unsafe extern fn block_data_order(state: &mut [u64; MAX_CHAINING_LEN / 8],
                                      data: *const u8,
                                      num: c::size_t) {
    let data = data as *const [u8; BLOCK_LEN];
    let blocks = core::slice::from_raw_parts(data, num);
    block_data_order_safe(state, blocks);
}

const K: [u32; 64] =
    [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
     0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
     0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
     0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
     0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
     0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

#[inline(always)]
fn sigma_1(e: u32) -> u32 {
    e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25)
}

#[inline(always)]
fn sigma_0(a: u32) -> u32 {
    a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22)
}

#[inline(always)]
fn ch(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ (!e & g)
}

#[inline(always)]
fn temp1(h: u32, s1: u32, ch: u32, k: u32, w: u32) -> u32 {
    h.wrapping_add(s1).wrapping_add(ch).wrapping_add(k).wrapping_add(w)
}

#[inline(always)]
fn maj(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

fn block_data_order_safe(state: &mut [u64; MAX_CHAINING_LEN / 8], blocks: &[[u8; BLOCK_LEN]]) {
    let state = polyfill::slice::u64_as_u32_mut(state);
    let state = &mut state[..CHAINING_WORDS];
    let state = slice_as_array_ref_mut!(state, CHAINING_WORDS).unwrap();

    let mut w: [u32; 64] = [0; 64];
    for block in blocks {
        for i in 0..16 {
            let offset = i * 4;
            let word = slice_as_array_ref!(&block[offset..][..4], 4).unwrap();
            w[i] = polyfill::slice::u32_from_be_u8(word);
        }

        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a: u32 = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        macro_rules! iter_4 {
            ($i:expr) => {
                {
                    let s1_0: u32 = sigma_1(e);
                    let ch_0: u32 = ch(e, f, g);
                    let temp1_0: u32 = temp1(h, s1_0, ch_0, K[$i], w[$i]);
                    let s0_0: u32 = sigma_0(a);
                    let maj_0: u32 = maj(a, b, c);
                    let temp2_0: u32 = s0_0.wrapping_add(maj_0);

                    let e_0: u32 = d.wrapping_add(temp1_0);
                    let a_0: u32 = temp1_0.wrapping_add(temp2_0);

                    let ch_1: u32 = ch(e_0, e, f);
                    let s1_1: u32 = sigma_1(e_0);
                    let temp1_1: u32 = temp1(g, s1_1, ch_1, K[$i + 1], w[$i + 1]);


                    let s0_1: u32 = sigma_0(a_0);
                    let maj_1: u32 = maj(a_0, a, b);
                    let temp2_1: u32 = s0_1.wrapping_add(maj_1);

                    let e_1 = c.wrapping_add(temp1_1);
                    let a_1 = temp1_1.wrapping_add(temp2_1);

                    let s1_2 = sigma_1(e_1);
                    let ch_2 = ch(e_1, e_0, e);
                    let temp1_2 = temp1(f, s1_2, ch_2, K[$i + 2], w[$i + 2]);
                    let s0_2 = sigma_0(a_1);
                    let maj_2 = maj(a_1, a_0, a);
                    let temp2_2 = s0_2.wrapping_add(maj_2);

                    let e_2 = b.wrapping_add(temp1_2);
                    let a_2 = temp1_2.wrapping_add(temp2_2);

                    let ch_3 = ch(e_2, e_1, e_0);
                    let s1_3 = sigma_1(e_2);
                    let temp1_3 = temp1(e, s1_3, ch_3, K[$i + 3], w[$i + 3]);

                    let s0_3 = sigma_0(a_2);
                    let maj_3 = maj(a_2, a_1, a_0);
                    let temp2_3 = s0_3.wrapping_add(maj_3);

                    h = e_0;
                    g = e_1;
                    f = e_2;
                    e = a.wrapping_add(temp1_3);
                    d = a_0;
                    c = a_1;
                    b = a_2;
                    a = temp1_3.wrapping_add(temp2_3);
                }
            }
        }
        iter_4!(0);
        iter_4!(4);
        iter_4!(8);
        iter_4!(12);
        iter_4!(16);
        iter_4!(20);
        iter_4!(24);
        iter_4!(28);
        iter_4!(32);
        iter_4!(36);
        iter_4!(40);
        iter_4!(44);
        iter_4!(48);
        iter_4!(52);
        iter_4!(56);
        iter_4!(60);

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}


#[cfg(test)]
mod tests {

    use super::super::{digest, SHA256};

    #[test]
    fn sha256_foobar() {
        let expected: [u8; 32] = [
            0xc3, 0xab, 0x8f, 0xf1, 0x37, 0x20, 0xe8, 0xad,
            0x90, 0x47, 0xdd, 0x39, 0x46, 0x6b, 0x3c, 0x89,
            0x74, 0xe5, 0x92, 0xc2, 0xfa, 0x38, 0x3d, 0x4a,
            0x39, 0x60, 0x71, 0x4c, 0xae, 0xf0, 0xc4, 0xf2
        ];
        let input = "foobar";
        let output = digest(&SHA256, input.as_bytes());

        assert_eq!(expected, output.as_ref())
    }
}
