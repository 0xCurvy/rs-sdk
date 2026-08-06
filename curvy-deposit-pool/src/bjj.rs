//! BabyJubJub key conversion for deposit-pool addresses.

use curvy_core::eddsa::ScalarSigningKey;
use curvy_core::field::Fr;

/// Decompress a `BjjPublicKey` into affine coordinates.
pub fn decompress(compressed: &[u8]) -> Option<(Fr, Fr)> {
    use babyjubjub_ec::elliptic_curve::group::GroupEncoding;
    let bytes: [u8; 32] = compressed.try_into().ok()?;
    let point = Option::<babyjubjub_ec::ProjectivePoint>::from(
        babyjubjub_ec::ProjectivePoint::from_bytes(&babyjubjub_ec::GroupRepr(bytes)),
    )?;
    let affine = babyjubjub_ec::AffinePoint::from(point);
    // Decimal encoding bridges the distinct field types.
    Some((
        curvy_core::field::fr_from_dec(&affine.x().to_string()),
        curvy_core::field::fr_from_dec(&affine.y().to_string()),
    ))
}

/// Build a signing key from a big-endian deposit secret.
pub fn signing_key(secret_be: &[u8; 32]) -> Option<ScalarSigningKey> {
    let mut le = *secret_be;
    le.reverse();
    ScalarSigningKey::from_le_bytes(le).ok()
}

/// Derive the compressed public key for a deposit secret.
pub fn compressed_from_secret(secret_be: &[u8; 32]) -> Option<[u8; 32]> {
    use hopr_types::crypto::keypairs::{BjjKeypair, Keypair};
    let keypair = BjjKeypair::from_secret(secret_be).ok()?;
    keypair.public().as_ref().try_into().ok()
}

/// Generate a shared secret for a new allocation.
pub fn fresh_shared_secret() -> Fr {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("system randomness");
    curvy_core::field::fr_from_biguint(&num_bigint::BigUint::from_bytes_be(&bytes))
}

#[cfg(test)]
mod tests {
    use hopr_types::crypto::keypairs::{BjjKeypair, Keypair};

    /// Scalar derivation agrees across field representations.
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
        let curvy = ScalarSigningKey::from_decimal("1").expect("scalar 1");
        assert_eq!(fr_to_dec(&curvy.verifying_key().x()), CIRCOMLIB_BASE8_X);

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
