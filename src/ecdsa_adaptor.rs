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

//! # ECDSA Adaptor Signature Module
//! Support for ECDSA single-signer adaptor signatures
//!

// How do I import ffi?

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct AdaptorSignature(ffi::AdaptorSignature);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct AdaptorProof(ffi::AdaptorProof);