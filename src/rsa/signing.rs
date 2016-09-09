// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#![allow(unsafe_code)]

/// RSA PKCS#1 1.5 signatures.

use {bssl, c, der, digest, error};
use rand;
use std;
use super::{
    BIGNUM,
    GFp_BN_free,
    BN_MONT_CTX,
    GFp_BN_MONT_CTX_free,
    PositiveInteger,

    RSAPadding,
};
use untrusted;

impl RSAPadding {
    // Implement padding procedure per EMSA-PKCS1-v1_5,
    // https://tools.ietf.org/html/rfc3447#section-9.2.
    fn pad(&self, msg: &[u8], out: &mut [u8])
           -> Result<(), error::Unspecified> {
        let digest_len = self.digestinfo_prefix.len() +
                         self.digest_alg.output_len;

        // Require at least 8 bytes of padding. Since we disallow keys smaller
        // than 2048 bits, this should never happen anyway.
        debug_assert!(out.len() >= digest_len + 11);
        let pad_len = out.len() - digest_len - 3;
        out[0] = 0;
        out[1] = 1;
        for i in 0..pad_len {
            out[2 + i] = 0xff;
        }
        out[2 + pad_len] = 0;

        let (digest_prefix, digest_dst) = out[3 + pad_len..].split_at_mut(
            self.digestinfo_prefix.len());
        digest_prefix.copy_from_slice(self.digestinfo_prefix);
        digest_dst.copy_from_slice(
            digest::digest(self.digest_alg, msg).as_ref());
        Ok(())
    }
}

/// An RSA key pair, used for signing. Feature: `rsa_signing`.
///
/// After constructing an `RSAKeyPair`, construct one or more
/// `RSASigningState`s that reference the `RSAKeyPair` and use
/// `RSASigningState::sign()` to generate signatures. See `ring::signature`'s
/// module-level documentation for an example.
pub struct RSAKeyPair {
    rsa: RSA,
}

impl RSAKeyPair {
    /// Parse a private key in DER-encoded ASN.1 `RSAPrivateKey` form (see
    /// [RFC 3447 Appendix A.1.2]).
    ///
    /// Only two-prime keys (version 0) keys are supported. The public modulus
    /// (n) must be at least 2048 bits. Currently, the public modulus must be
    /// no larger than 4096 bits.
    ///
    /// Here's one way to generate a key in the required format using OpenSSL:
    ///
    /// ```sh
    /// openssl genpkey -algorithm RSA \
    ///                 -pkeyopt rsa_keygen_bits:2048 \
    ///                 -outform der \
    ///                 -out private_key.der
    /// ```
    ///
    /// Often, keys generated for use in OpenSSL-based software are
    /// encoded in PEM format, which is not supported by *ring*. PEM-encoded
    /// keys that are in `RSAPrivateKey` format can be decoded into the using
    /// an OpenSSL command like this:
    ///
    /// ```sh
    /// openssl rsa -in private_key.pem -outform DER -out private_key.der
    /// ```
    ///
    /// If these commands don't work, it is likely that the private key is in a
    /// different format like PKCS#8, which isn't supported yet. An upcoming
    /// version of *ring* will likely replace the support for the
    /// `RSAPrivateKey` format with support for the PKCS#8 format.
    ///
    /// [RFC 3447 Appendix A.1.2]:
    ///     https://tools.ietf.org/html/rfc3447#appendix-A.1.2
    pub fn from_der(input: untrusted::Input)
                    -> Result<RSAKeyPair, error::Unspecified> {
        input.read_all(error::Unspecified, |input| {
            der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
                let version = try!(der::small_nonnegative_integer(input));
                if version != 0 {
                    return Err(error::Unspecified);
                }
                let n = try!(PositiveInteger::from_der(input));
                let mut e = try!(PositiveInteger::from_der(input));
                let d = try!(PositiveInteger::from_der(input));
                let p = try!(PositiveInteger::from_der(input));
                let q = try!(PositiveInteger::from_der(input));
                let mut dmp1 = try!(PositiveInteger::from_der(input));
                let mut dmq1 = try!(PositiveInteger::from_der(input));
                let mut iqmp = try!(PositiveInteger::from_der(input));
                let mut rsa = RSA {
                    e: e.into_raw(), dmp1: dmp1.into_raw(),
                    dmq1: dmq1.into_raw(), iqmp: iqmp.into_raw(),
                    mont_n: std::ptr::null_mut(), mont_p: std::ptr::null_mut(),
                    mont_q: std::ptr::null_mut(),
                    mont_qq: std::ptr::null_mut(),
                    qmn_mont: std::ptr::null_mut(),
                    iqmp_mont: std::ptr::null_mut(),
                };
                try!(bssl::map_result(unsafe {
                    GFp_rsa_new_end(&mut rsa, n.as_ref(), d.as_ref(),
                                    p.as_ref(), q.as_ref())
                }));
                Ok(RSAKeyPair { rsa: rsa })
            })
        })
    }

    /// Returns the length in bytes of the key pair's public modulus.
    ///
    /// A signature has the same length as the public modulus.
    pub fn public_modulus_len(&self) -> usize {
        unsafe { GFp_RSA_size(&self.rsa) }
    }
}

impl Drop for RSAKeyPair {
    fn drop(&mut self) {
        unsafe {
            GFp_BN_free(self.rsa.e);
            GFp_BN_free(self.rsa.dmp1);
            GFp_BN_free(self.rsa.dmq1);
            GFp_BN_free(self.rsa.iqmp);
            GFp_BN_MONT_CTX_free(self.rsa.mont_n);
            GFp_BN_MONT_CTX_free(self.rsa.mont_p);
            GFp_BN_MONT_CTX_free(self.rsa.mont_q);
            GFp_BN_MONT_CTX_free(self.rsa.mont_qq);
            GFp_BN_free(self.rsa.qmn_mont);
            GFp_BN_free(self.rsa.iqmp_mont);
        }
    }
}

unsafe impl Send for RSAKeyPair {}
unsafe impl Sync for RSAKeyPair {}

/// Needs to be kept in sync with `struct rsa_st` (in `include/openssl/rsa.h`).
#[repr(C)]
struct RSA {
    e: *mut BIGNUM,
    dmp1: *mut BIGNUM,
    dmq1: *mut BIGNUM,
    iqmp: *mut BIGNUM,
    mont_n: *mut BN_MONT_CTX,
    mont_p: *mut BN_MONT_CTX,
    mont_q: *mut BN_MONT_CTX,
    mont_qq: *mut BN_MONT_CTX,
    qmn_mont: *mut BIGNUM,
    iqmp_mont: *mut BIGNUM,
}


/// State used for RSA Signing. Feature: `rsa_signing`.
///
/// # Performance Considerations
///
/// Every time `sign` is called, some internal state is updated. Usually the
/// state update is relatively cheap, but the first time, and periodically, a
/// relatively expensive computation (computing the modular inverse of a random
/// number modulo the public key modulus, for blinding the RSA exponentiation)
/// will be done. Reusing the same `RSASigningState` when generating multiple
/// signatures improves the computational efficiency of signing by minimizing
/// the frequency of the expensive computations.
///
/// `RSASigningState` is not `Sync`; i.e. concurrent use of an `sign()` on the
/// same `RSASigningState` from multiple threads is not allowed. An
/// `RSASigningState` can be wrapped in a `Mutex` to be shared between threads;
/// this would maximize the computational efficiency (as explained above) and
/// minimizes memory usage, but it also minimizes concurrency because all the
/// calls to `sign()` would be serialized. To increases concurrency one could
/// create multiple `RSASigningState`s that share the same `RSAKeyPair`; the
/// number of `RSASigningState` in use at once determines the concurrency
/// factor. This increases memory usage, but only by a small amount, as each
/// `RSASigningState` is much smaller than the `RSAKeyPair` that they would
/// share. Using multiple `RSASigningState` per `RSAKeyPair` may also decrease
/// computational efficiency by increasing the frequency of the expensive
/// modular inversions; managing a pool of `RSASigningState`s in a
/// most-recently-used fashion would improve the computational efficiency.
pub struct RSASigningState {
    key_pair: std::sync::Arc<RSAKeyPair>,
    blinding: Blinding,
}

impl RSASigningState {
    /// Construct an `RSASigningState` for the given `RSAKeyPair`.
    pub fn new(key_pair: std::sync::Arc<RSAKeyPair>)
               -> Result<Self, error::Unspecified> {
        let blinding = unsafe { GFp_BN_BLINDING_new() };
        if blinding.is_null() {
            return Err(error::Unspecified);
        }
        Ok(RSASigningState {
            key_pair: key_pair,
            blinding: Blinding { blinding: blinding },
        })
    }

    /// The `RSAKeyPair`. This can be used, for example, to access the key
    /// pair's public key through the `RSASigningState`.
    pub fn key_pair(&self) -> &RSAKeyPair { self.key_pair.as_ref() }

    /// Sign `msg`. `msg` is digested using the digest algorithm from
    /// `padding_alg` and the digest is then padded using the padding algorithm
    /// from `padding_alg`. The signature it written into `signature`;
    /// `signature`'s length must be exactly the length returned by
    /// `public_modulus_len()`. `rng` is used for blinding the message during
    /// signing, to mitigate some side-channel (e.g. timing) attacks.
    ///
    /// Many other crypto libraries have signing functions that takes a
    /// precomputed digest as input, instead of the message to digest. This
    /// function does *not* take a precomputed digest; instead, `sign`
    /// calculates the digest itself.
    ///
    /// Lots of effort has been made to make the signing operations close to
    /// constant time to protect the private key from side channel attacks. On
    /// x86-64, this is done pretty well, but not perfectly. On other
    /// platforms, it is done less perfectly. To help mitigate the current
    /// imperfections, and for defense-in-depth, base blinding is always done.
    /// Exponent blinding is not done, but it may be done in the future.
    pub fn sign(&mut self, padding_alg: &'static RSAPadding,
                rng: &rand::SecureRandom, msg: &[u8], signature: &mut [u8])
                -> Result<(), error::Unspecified> {
        if signature.len() != self.key_pair.public_modulus_len() {
            return Err(error::Unspecified);
        }

        try!(padding_alg.pad(msg, signature));
        let mut rand = rand::RAND::new(rng);
        bssl::map_result(unsafe {
            GFp_rsa_private_transform(&self.key_pair.rsa,
                                      signature.as_mut_ptr(), signature.len(),
                                      self.blinding.blinding, &mut rand)
        })
    }
}

struct Blinding {
    blinding: *mut BN_BLINDING,
}

impl Drop for Blinding {
    fn drop(&mut self) { unsafe { GFp_BN_BLINDING_free(self.blinding) } }
}

unsafe impl Send for Blinding {}

/// Needs to be kept in sync with `bn_blinding_st` in `crypto/rsa/blinding.c`.
#[allow(non_camel_case_types)]
#[repr(C)]
struct BN_BLINDING {
    a: *mut BIGNUM,
    ai: *mut BIGNUM,
    counter: u32,
}


extern {
    fn GFp_BN_BLINDING_new() -> *mut BN_BLINDING;
    fn GFp_BN_BLINDING_free(b: *mut BN_BLINDING);
    fn GFp_rsa_new_end(rsa: *mut RSA, n: &BIGNUM, d: &BIGNUM, p: &BIGNUM,
                       q: &BIGNUM) -> c::int;
    fn GFp_RSA_size(rsa: *const RSA) -> c::size_t;
}

#[allow(improper_ctypes)]
extern {
    fn GFp_rsa_private_transform(rsa: *const RSA, inout: *mut u8,
                                 len: c::size_t, blinding: *mut BN_BLINDING,
                                 rng: *mut rand::RAND) -> c::int;
}


#[cfg(not(feature = "native_rust"))]
#[cfg(test)]
mod tests {
    use rand;
    use std;
    use test;

    use super::*;
    use super::super::{RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512};
    use untrusted;

    extern {
        static GFp_BN_BLINDING_COUNTER: u32;
    }

    #[test]
    fn test_signature_rsa_pkcs1_sign() {
        let rng = rand::SystemRandom::new();
        test::from_file("src/rsa/rsa_pkcs1_sign_tests.txt",
                        |section, test_case| {
            let digest_name = test_case.consume_string("Digest");
            // Note that SHA-1 isn't recognized here because we don't expose
            // PKCS#1 SHA-1 signing, because we don't have test vectors for it.
            let alg = if digest_name == "SHA256" {
                &RSA_PKCS1_SHA256
            } else if digest_name == "SHA384" {
                &RSA_PKCS1_SHA384
            } else if digest_name == "SHA512" {
                &RSA_PKCS1_SHA512
            } else {
                panic!("Unsupported digest: {}", digest_name);
            };

            let private_key = test_case.consume_bytes("Key");
            let msg = test_case.consume_bytes("Msg");
            let expected = test_case.consume_bytes("Sig");
            let result = test_case.consume_string("Result");

            let private_key = untrusted::Input::from(&private_key);
            let key_pair = RSAKeyPair::from_der(private_key);
            if key_pair.is_err() && result == "Fail-Invalid-Key" {
                return Ok(());
            }
            let key_pair = key_pair.unwrap();
            let key_pair = std::sync::Arc::new(key_pair);

            // XXX: This test is too slow on Android ARM Travis CI builds.
            // TODO: re-enable these tests on Android ARM.
            if section == "Skipped on Android ARM due to Travis CI Timeouts" &&
               cfg!(all(target_os = "android", target_arch = "arm")) {
                return Ok(());
            }
            let mut signing_state = RSASigningState::new(key_pair).unwrap();
            let mut actual: std::vec::Vec<u8> =
                vec![0; signing_state.key_pair().public_modulus_len()];
            signing_state.sign(alg, &rng, &msg, actual.as_mut_slice()).unwrap();
            assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
            Ok(())
        });
    }

    // `RSAKeyPair::sign` requires that the output buffer is the same length as
    // the public key modulus. Test what happens when it isn't the same length.
    #[test]
    fn test_signature_rsa_pkcs1_sign_output_buffer_len() {
        // Sign the message "hello, world", using PKCS#1 v1.5 padding and the
        // SHA256 digest algorithm.
        const MESSAGE: &'static [u8] = b"hello, world";
        let rng = rand::SystemRandom::new();

        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = RSAKeyPair::from_der(key_bytes_der).unwrap();
        let key_pair = std::sync::Arc::new(key_pair);
        let mut signing_state = RSASigningState::new(key_pair).unwrap();

        // The output buffer is one byte too short.
        let mut signature =
            vec![0; signing_state.key_pair().public_modulus_len() - 1];

        assert!(signing_state.sign(&RSA_PKCS1_SHA256, &rng, MESSAGE,
                                   &mut signature).is_err());

        // The output buffer is the right length.
        signature.push(0);
        assert!(signing_state.sign(&RSA_PKCS1_SHA256, &rng, MESSAGE,
                                   &mut signature).is_ok());


        // The output buffer is one byte too long.
        signature.push(0);
        assert!(signing_state.sign(&RSA_PKCS1_SHA256, &rng, MESSAGE,
                                   &mut signature).is_err());
    }

    // Once the `BN_BLINDING` in an `RSAKeyPair` has been used
    // `GFp_BN_BLINDING_COUNTER` times, a new blinding should be created. we
    // don't check that a new blinding was created; we just make sure to
    // exercise the code path, so this is basically a coverage test.
    #[test]
    fn test_signature_rsa_pkcs1_sign_blinding_reuse() {
        const MESSAGE: &'static [u8] = b"hello, world";
        let rng = rand::SystemRandom::new();

        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = RSAKeyPair::from_der(key_bytes_der).unwrap();
        let key_pair = std::sync::Arc::new(key_pair);
        let mut signature = vec![0; key_pair.public_modulus_len()];

        let mut signing_state = RSASigningState::new(key_pair).unwrap();

        for _ in 0..(GFp_BN_BLINDING_COUNTER + 1) {
            let prev_counter =
                unsafe { (*signing_state.blinding.blinding).counter };

            let _ = signing_state.sign(&RSA_PKCS1_SHA256, &rng, MESSAGE, &mut signature);

            let counter = unsafe { (*signing_state.blinding.blinding).counter };

            assert_eq!(counter, (prev_counter + 1) % GFp_BN_BLINDING_COUNTER);
        }
    }

    // In `crypto/rsa/blinding.c`, when `bn_blinding_create_param` fails to
    // randomly generate an invertible blinding factor too many times in a
    // loop, it returns an error. Check that we observe this.
    #[test]
    fn test_signature_rsa_pkcs1_sign_blinding_creation_failure() {
        const MESSAGE: &'static [u8] = b"hello, world";

        // Stub RNG that is constantly 0. In `bn_blinding_create_param`, this
        // causes the candidate blinding factors to always be 0, which has no
        // inverse, so `BN_mod_inverse_no_branch` fails.
        let rng = rand::test_util::FixedByteRandom { byte: 0x00 };

        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = RSAKeyPair::from_der(key_bytes_der).unwrap();
        let key_pair = std::sync::Arc::new(key_pair);
        let mut signing_state = RSASigningState::new(key_pair).unwrap();
        let mut signature =
            vec![0; signing_state.key_pair().public_modulus_len()];
        let result =
            signing_state.sign(&RSA_PKCS1_SHA256, &rng, MESSAGE, &mut signature);

        assert!(result.is_err());
    }

    #[test]
    fn test_sync_and_send() {
        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = RSAKeyPair::from_der(key_bytes_der).unwrap();
        let key_pair = std::sync::Arc::new(key_pair);

        let _: &Send = &key_pair;
        let _: &Sync = &key_pair;

        let signing_state = RSASigningState::new(key_pair).unwrap();
        let _: &Send = &signing_state;
        // TODO: Test that signing_state is NOT Sync; i.e.
        // `let _: &Sync = &signing_state;` must fail
    }
}
