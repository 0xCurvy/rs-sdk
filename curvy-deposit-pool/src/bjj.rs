//! Bridging HOPR's BabyJubJub keys to Curvy's.
//!
//! The two sides run independent implementations of the same curve - HOPR uses
//! `babyjubjub-ec`, Curvy hand-rolls over arkworks with circomlib's `Base8` subgroup
//! generator. Agreement is therefore a fact to be tested, not assumed: if the two
//! derived different points from one scalar, every PIX deposit address would name a
//! note nobody could spend, and nothing in either type system would say so.

use curvy_core::eddsa::ScalarSigningKey;
use curvy_core::field::Fr;

/// Decompress a HOPR `BjjPublicKey` (32-byte compressed point) into Curvy's affine
/// `(x, y)` field-element pair.
///
/// Parsing goes through `babyjubjub-ec` - the same crate that produced the bytes - so
/// the compression convention is consistent by construction rather than by assumption.
pub fn decompress(compressed: &[u8]) -> Option<(Fr, Fr)> {
    use babyjubjub_ec::elliptic_curve::group::GroupEncoding;
    let bytes: [u8; 32] = compressed.try_into().ok()?;
    let point = Option::<babyjubjub_ec::ProjectivePoint>::from(
        babyjubjub_ec::ProjectivePoint::from_bytes(&babyjubjub_ec::GroupRepr(bytes)),
    )?;
    let affine = babyjubjub_ec::AffinePoint::from(point);
    // `babyjubjub-ec` and `curvy-core` are both arkworks-based but resolve DIFFERENT
    // `ark-ff` versions, so their `Fp` types are nominally distinct. Round-tripping
    // through the canonical decimal string is version-independent and exact.
    Some((
        curvy_core::field::fr_from_dec(&affine.x().to_string()),
        curvy_core::field::fr_from_dec(&affine.y().to_string()),
    ))
}

/// Build Curvy's signing key from a HOPR `PixDepositSecret`'s 32 bytes.
///
/// HOPR encodes the scalar BIG-endian (`BjjKeypair::from_secret` on `[0u8; 31] ++ [1]`
/// yields `Base8`, i.e. scalar 1) while Curvy's constructor takes little-endian, so the
/// bytes must be reversed. Both sides otherwise agree - same curve, same `Base8`
/// generator - which is why this is a byte-order bug rather than a design mismatch, and
/// why it would have been invisible: every deposit address would simply have named a
/// note nobody could spend.
pub fn signing_key(secret_be: &[u8; 32]) -> Option<ScalarSigningKey> {
    let mut le = *secret_be;
    le.reverse();
    ScalarSigningKey::from_le_bytes(le).ok()
}

/// The 32-byte `BjjPublicKey` encoding HOPR would use for the address owning `secret`.
///
/// Derived with HOPR's own keypair type rather than by re-compressing a Curvy point:
/// the bytes must match what HOPR hands us in a `PixDepositAddress` exactly, and the
/// safest way to guarantee that is to produce them the same way HOPR does.
pub fn compressed_from_secret(secret_be: &[u8; 32]) -> Option<[u8; 32]> {
    use hopr_types::crypto::keypairs::{BjjKeypair, Keypair};
    let keypair = BjjKeypair::from_secret(secret_be).ok()?;
    keypair.public().as_ref().try_into().ok()
}

/// A fresh shared secret for a new allocation.
///
/// Per-note unlinkability rests on this being unpredictable: `ownerHash` is
/// `poseidon(ownerPub, sharedSecret)`, so a reused or guessable secret would let an
/// observer link two allocations to one deposit address.
pub fn fresh_shared_secret() -> Fr {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("system randomness");
    curvy_core::field::fr_from_biguint(&num_bigint::BigUint::from_bytes_be(&bytes))
}

#[cfg(test)]
mod tests {
    use hopr_types::crypto::keypairs::{BjjKeypair, Keypair};

    /// The load-bearing interop fact: one scalar, one point, on both sides.
    #[test]
    fn hopr_and_curvy_derive_the_same_point_from_one_scalar() {
        for seed in [1u8, 7, 42, 200] {
            let mut secret = [0u8; 32];
            secret[31] = seed;

            let hopr = BjjKeypair::from_secret(&secret).expect("valid bjj secret");
            let hopr_xy = super::decompress(hopr.public().as_ref()).expect("decompressible");

            let curvy = super::signing_key(&secret).expect("valid curvy scalar");
            let curvy_xy = curvy.verifying_key().as_tuple();

            assert_eq!(
                hopr_xy, curvy_xy,
                "HOPR and Curvy disagree on the public key for secret ending {seed}"
            );
        }
    }
}

#[cfg(test)]
mod generator_tests {
    use curvy_core::babyjubjub::BASE8;
    use curvy_core::eddsa::ScalarSigningKey;
    use curvy_core::field::fr_to_dec;
    use hopr_types::crypto::keypairs::{BjjKeypair, Keypair};

    /// circomlib's `Base8`, the order-`subOrder` subgroup generator.
    const CIRCOMLIB_BASE8_X: &str =
        "5299619240641551281634865583518297030282874472190772894086521144482721001553";
    const CIRCOMLIB_BASE8_Y: &str =
        "16950150798460657717958625567821834550301663161624707787222815936182638968203";

    #[test]
    fn curvy_uses_circomlibs_base8() {
        assert_eq!(fr_to_dec(&BASE8.0), CIRCOMLIB_BASE8_X);
        assert_eq!(fr_to_dec(&BASE8.1), CIRCOMLIB_BASE8_Y);
    }

    #[test]
    fn scalar_one_maps_to_base8_on_both_sides() {
        // Curvy, given the scalar 1 unambiguously (decimal, no byte order involved).
        let curvy = ScalarSigningKey::from_decimal("1").expect("scalar 1");
        assert_eq!(fr_to_dec(&curvy.verifying_key().x()), CIRCOMLIB_BASE8_X);

        // HOPR, given 32 bytes whose LAST byte is 1 - which it reads as the scalar 1,
        // confirming a big-endian secret encoding rather than a different generator.
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let hopr = super::decompress(
            BjjKeypair::from_secret(&secret)
                .expect("valid secret")
                .public()
                .as_ref(),
        )
        .expect("decompressible");
        assert_eq!(fr_to_dec(&hopr.0), CIRCOMLIB_BASE8_X);
    }
}
