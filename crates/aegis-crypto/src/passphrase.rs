//! Argon2id passphrase KDF. See AEGIS.Plan.V0.2.md Section 2.
//!
//! Reference: RFC 9106 (Argon2). Production parameters are fixed by
//! spec Section 2 and are not user-configurable (Security-by-Default,
//! spec Section 4/7A — no toggle may decrease these).

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Spec Section 2: Memory 64 MiB, Iterations 4, Parallelism 4.
pub const PRODUCTION_PARAMS: Argon2Params = Argon2Params {
    memory_kib: 64 * 1024,
    iterations: 4,
    parallelism: 4,
};

/// Derive a master key using the spec-mandated production parameters.
///
/// **This is the entry point production code must use.** It pins
/// [`PRODUCTION_PARAMS`] so no caller — and no configuration toggle —
/// can weaken the KDF, which is what spec Section 7A (Security by
/// Default: no toggle may decrease these) requires. The general
/// [`derive_master_key`] exists only so the RFC 9106 known-answer test
/// can supply the RFC's deliberately weak parameters.
///
/// # Errors
///
/// Propagates `argon2::Error` for an invalid `salt` (RFC 9106 requires
/// at least 8 bytes), an over-long `associated_data`, or an `output`
/// length outside Argon2's permitted range.
pub fn derive_master_key_production(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    output: &mut [u8],
) -> Result<(), argon2::Error> {
    derive_master_key(
        password,
        salt,
        secret,
        associated_data,
        &PRODUCTION_PARAMS,
        output,
    )
}

/// Derive a master key with caller-supplied Argon2id parameters.
///
/// **Not for production use — call [`derive_master_key_production`]
/// instead.** This form exists solely so the RFC 9106 known-answer test
/// can pass the RFC's weak vector parameters (32 KiB, t=3). Any
/// production caller that reaches for this can silently weaken the
/// passphrase KDF, which spec Section 7A forbids.
///
/// # Errors
///
/// Propagates `argon2::Error` for parameters outside Argon2's permitted
/// ranges, an invalid `salt`, an over-long `associated_data`, or an
/// unsupported `output` length.
#[doc(hidden)]
pub fn derive_master_key(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    params: &Argon2Params,
    output: &mut [u8],
) -> Result<(), argon2::Error> {
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(params.memory_kib)
        .t_cost(params.iterations)
        .p_cost(params.parallelism)
        .output_len(output.len());
    if !associated_data.is_empty() {
        builder.data(AssociatedData::new(associated_data)?);
    }
    let argon2_params = builder.build()?;

    let argon2 = if secret.is_empty() {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params)
    } else {
        Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, argon2_params)?
    };

    argon2.hash_password_into(password, salt, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_params_match_spec() {
        assert_eq!(PRODUCTION_PARAMS.memory_kib, 64 * 1024);
        assert_eq!(PRODUCTION_PARAMS.iterations, 4);
        assert_eq!(PRODUCTION_PARAMS.parallelism, 4);
    }

    /// The production entry point must pin the spec parameters — not
    /// merely default to them.
    #[test]
    fn production_entry_point_uses_the_spec_parameters() {
        let mut via_production = [0u8; 32];
        derive_master_key_production(
            b"correct horse battery staple",
            b"somesalt12345678",
            b"",
            b"",
            &mut via_production,
        )
        .unwrap();

        let mut via_explicit_params = [0u8; 32];
        derive_master_key(
            b"correct horse battery staple",
            b"somesalt12345678",
            b"",
            b"",
            &PRODUCTION_PARAMS,
            &mut via_explicit_params,
        )
        .unwrap();

        assert_eq!(via_production, via_explicit_params);

        // And is genuinely stronger than the weak KAT parameters, so a
        // future edit that silently downgrades PRODUCTION_PARAMS to the
        // test values would be caught here too.
        let mut via_weak_params = [0u8; 32];
        derive_master_key(
            b"correct horse battery staple",
            b"somesalt12345678",
            b"",
            b"",
            &Argon2Params {
                memory_kib: 32,
                iterations: 3,
                parallelism: 4,
            },
            &mut via_weak_params,
        )
        .unwrap();
        assert_ne!(via_production, via_weak_params);
    }

    #[test]
    fn same_inputs_are_deterministic() {
        let params = Argon2Params {
            memory_kib: 19 * 1024,
            iterations: 2,
            parallelism: 1,
        };
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_master_key(b"password", b"somesalt12345678", b"", b"", &params, &mut out1)
            .unwrap();
        derive_master_key(b"password", b"somesalt12345678", b"", b"", &params, &mut out2)
            .unwrap();
        assert_eq!(out1, out2);
    }

    /// RFC 9106 Section 5.3 official Argon2id test vector, transcribed
    /// directly from the RFC text. Verifies our wrapper's plumbing
    /// against an official KAT.
    #[test]
    fn argon2id_official_kat_rfc9106() {
        let password = [0x01u8; 32];
        let salt = [0x02u8; 16];
        let secret = [0x03u8; 8];
        let associated_data = [0x04u8; 12];
        let params = Argon2Params {
            memory_kib: 32,
            iterations: 3,
            parallelism: 4,
        };
        let expected_tag = hex::decode(
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
        )
        .unwrap();

        let mut out = vec![0u8; 32];
        derive_master_key(&password, &salt, &secret, &associated_data, &params, &mut out)
            .unwrap();
        assert_eq!(out, expected_tag);
    }
}
