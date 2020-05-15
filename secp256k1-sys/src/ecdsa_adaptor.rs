// Bitcoin secp256k1 bindings
// Written in 2020 by
//   Nadav Kohen
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # FFI of the ecdsa_adaptor module


/// Library-internal representation of a Secp256k1 adaptor signature
#[repr(C)]
pub struct AdaptorSignature([c_uchar; 65]);
impl_array_newtype!(AdaptorSignature, c_uchar, 65);
impl_raw_debug!(AdaptorSignature);

impl AdaptorSignature {
    /// Create a new (zeroed) signature usable for the FFI interface
    pub fn new() -> AdaptorSignature { AdaptorSignature([0; 65]) }
}

impl Default for AdaptorSignature {
    fn default() -> Self {
        AdaptorSignature::new()
    }
}

/// Library-internal representation of a Secp256k1 adaptor proof
#[repr(C)]
pub struct AdaptorProof([c_uchar; 97]);
impl_array_newtype!(AdaptorProof, c_uchar, 97);
impl_raw_debug!(AdaptorProof);

impl AdaptorProof {
    /// Create a new (zeroed) signature usable for the FFI interface
    pub fn new() -> AdaptorProof { AdaptorProof([0; 97]) }
}

impl Default for AdaptorProof {
    fn default() -> Self {
        AdaptorProof::new()
    }
}

#[cfg(not(feature = "fuzztarget"))]
extern "C" {
    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_1_2_ecdsa_adaptor_sig_verify")]
    pub fn secp256k1_ecdsa_adaptor_sig_verify(cx: *const Context,
                                              sig: *const AdaptorSignature,
                                              pk: *const PublicKey,
                                              msg32: *const c_uchar,
                                              adaptor: *const PublicKey,
                                              adaptor_proof: *const AdaptorProof)
                                              -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_1_2_ecdsa_adaptor_sign")]
    pub fn secp256k1_ecdsa_adaptor_sign(cx: *const Context,
                                        sig: *mut AdaptorSignature,
                                        adaptor_proof: *mut AdaptorProof,
                                        sk: *const c_uchar,
                                        adaptor: *const PublicKey,
                                        msg32: *const c_uchar)
                                        -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_1_2_ecdsa_adaptor_adapt")]
    pub fn secp256k1_ecdsa_adaptor_adapt(cx: *const Context,
                                         sig: *mut Signature,
                                         adaptor_secret: *const c_uchar,
                                         adaptor_sig: *const AdaptorSignature)
                                         -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_1_2_ecdsa_adaptor_extract_secret")]
    pub fn secp256k1_ecdsa_adaptor_extract_secret(cx: *const Context,
                                                  adaptor_secret: *mut c_uchar,
                                                  sig: *const Signature,
                                                  adaptor_sig: *const AdaptorSignature,
                                                  adaptor: *const PublicKey)
                                                  -> c_int;
}

#[cfg(feature = "fuzztarget")]
mod fuzz_dummy {
    pub unsafe fn secp256k1_ecdsa_adaptor_sign(cx: *const Context,
                                               sig: *mut AdaptorSignature,
                                               adaptor_proof: *mut AdaptorProof,
                                               sk: *const c_uchar,
                                               adaptor: *const PublicKey,
                                               msg32: *const c_uchar) -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        assert!((*cx).0 as u32 & SECP256K1_START_SIGN == SECP256K1_START_SIGN);
        if secp256k1_ec_seckey_verify(cx, sk) != 1 { return 0; }
        if test_pk_validate(cx, adaptor) != 1 { return 0; }
        unimplemented!()
    }

    pub unsafe fn secp256k1_ecdsa_adaptor_sig_verify(cx: *const Context,
                                                     sig: *const AdaptorSignature,
                                                     pk: *const PublicKey,
                                                     msg32: *const c_uchar,
                                                     adaptor: *const PublicKey,
                                                     adaptor_proof: *const AdaptorProof)
                                                     -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        assert!((*cx).0 as u32 & SECP256K1_START_SIGN == SECP256K1_START_VERIFY);
        if test_pk_validate(cx, pk) != 1 { return 0; }
        if test_pk_validate(cx, adaptor) != 1 { return 0; }
        unimplemented!()
    }

    pub unsafe fn secp256k1_ecdsa_adaptor_adapt(cx: *const Context,
                                                sig: *mut Signature,
                                                adaptor_secret: *const c_uchar,
                                                adaptor_sig: *const AdaptorSignature)
                                                -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        if secp256k1_ec_seckey_verify(cx, adaptor_secret) != 1 { return 0; }
        unimplemented!()
    }

    pub unsafe fn secp256k1_ecdsa_adaptor_extract_secret(cx: *const Context,
                                                         adaptor_secret: *mut c_uchar,
                                                         sig: *const Signature,
                                                         adaptor_sig: *const AdaptorSignature,
                                                         adaptor: *const PublicKey)
                                                         -> c_int {
        assert!(!cx.is_null() && (*cx).0 as u32 & !(SECP256K1_START_NONE | SECP256K1_START_VERIFY | SECP256K1_START_SIGN) == 0);
        assert!((*cx).0 as u32 & SECP256K1_START_SIGN == SECP256K1_START_SIGN);
        if test_pk_validate(cx, adaptor) != 1 { return 0; }
        unimplemented!()
    }
}
#[cfg(feature = "fuzztarget")]
pub use self::fuzz_dummy::*;