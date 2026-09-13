//! BLAKE3 Merkle tree over ciphertext-chunk hashes. See
//! `AEGIS.Plan.V0.2.md` Section 5 ("compute a BLAKE3 Merkle tree hash
//! across all chunks; peers verify each chunk's hash incrementally
//! during download, before writing to disk") and Section 9.1 (never
//! invent a novel construction; cite a published reference).
//!
//! # Reference
//!
//! The tree shape, leaf/node domain-separation prefixes, and audit-path
//! construction below are [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)
//! Section 2.1's Merkle Tree Hash (`MTH`) and Section 2.1.1's Merkle
//! audit path (`PATH`), with BLAKE3 substituted for SHA-256 as the hash
//! function — the same substitution pattern this workspace already uses
//! elsewhere (e.g. brainpool512r1 in place of the NIST curve in
//! `aegis_crypto`'s hybrid KEM combiner, which still cites NIST SP
//! 800-56C for the combiner *construction*). No part of the tree shape,
//! split rule, or domain separation below is our own invention.
//!
//! RFC 6962 splits at "the largest power of two smaller than `n`"
//! rather than the more common naive bottom-up pairing with the last
//! odd node either dropped or duplicated. This is deliberate on RFC
//! 6962's part: naively *duplicating* an unpaired last leaf to force an
//! even count (a scheme several early Merkle-tree implementations,
//! including an early Bitcoin one, used) lets an attacker who controls
//! the leaf contents craft a second, different leaf sequence with the
//! same root — the duplicated node collides with itself under
//! concatenation. RFC 6962's split-based `MTH` has no unpaired node at
//! any level to duplicate, and the `0x00`/`0x01` leaf/internal-node
//! prefixes below additionally prevent a leaf hash from ever being
//! confused with an internal node hash (a second, independent
//! second-preimage defence RFC 6962 also specifies). See
//! [`tests::naive_last_node_duplication_gives_a_different_root_than_rfc6962`]
//! for a test pinning that this implementation does not fall back to
//! that weaker scheme.

use crate::error::FileError;

/// Domain-separation prefix for a leaf hash. RFC 6962 §2.1: `MTH({d(0)})
/// = HASH(0x00 || d(0))`.
const LEAF_PREFIX: u8 = 0x00;

/// Domain-separation prefix for an internal node hash. RFC 6962 §2.1:
/// `MTH(D[n]) = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))` for `n > 1`.
const NODE_PREFIX: u8 = 0x01;

/// Hash one ciphertext chunk into a domain-separated Merkle leaf.
///
/// Callers building a [`MerkleTree`] over a file's ciphertext chunks —
/// [`crate::stream::encrypt_stream`] and [`crate::stream::decrypt_stream`]
/// both do this incrementally, one chunk at a time, as part of their
/// bounded-memory streaming loop — call this once per chunk and collect
/// the results into [`MerkleTree::from_leaf_hashes`]. The 32-byte leaf
/// hashes themselves (unlike the 4 MiB chunks they summarise) are cheap
/// to hold in memory for an entire file: even at the spec Section 5 cap
/// of 256 chunks (1 GiB ÷ 4 MiB), the leaf list is 8 KiB.
pub fn leaf_hash(chunk_ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(chunk_ciphertext);
    *hasher.finalize().as_bytes()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// The largest power of two strictly smaller than `n`. Panics if `n <
/// 2` (RFC 6962's split rule is only invoked for `n > 1`; every call
/// site below is already guarded by a length check to that effect).
fn largest_power_of_two_less_than(n: usize) -> usize {
    debug_assert!(n >= 2, "split rule is only defined for n > 1");
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// RFC 6962 §2.1 `MTH(D[n])`, computed over already-hashed leaves (each
/// entry is the output of [`leaf_hash`], i.e. `HASH(0x00 || d(i))`, not
/// raw chunk bytes).
fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        // RFC 6962 §2.1: "The hash of an empty list is the hash of an
        // empty string: MTH({}) = HASH()."
        0 => *blake3::hash(&[]).as_bytes(),
        // A single already-domain-separated leaf hash *is* MTH for a
        // one-element list; §2.1 defines `MTH({d(0)})` as the leaf hash
        // itself, not a further wrapping.
        1 => leaves[0],
        n => {
            let k = largest_power_of_two_less_than(n);
            let left = mth(&leaves[..k]);
            let right = mth(&leaves[k..]);
            node_hash(&left, &right)
        }
    }
}

/// One step of a [`MerkleProof`]'s audit path: the sibling hash at that
/// level, and which side of the parent node it occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofStep {
    /// The sibling subtree's hash at this level.
    pub sibling_hash: [u8; 32],
    /// `true` if the sibling is the *right* child of their shared
    /// parent (so verification computes `node_hash(current, sibling)`);
    /// `false` if the sibling is the left child (`node_hash(sibling,
    /// current)`).
    pub sibling_is_right: bool,
}

/// An RFC 6962 §2.1.1 Merkle audit path proving that a specific leaf
/// hash is included, at a specific index, in a tree with a specific
/// root — without needing the other leaves.
///
/// Not used by [`crate::stream::decrypt_stream`] itself, which already
/// holds every leaf (it must read every chunk to decrypt the file) and
/// so verifies the whole root directly. This exists as the public
/// primitive spec Section 9's `aegis-file` module description calls
/// for ("BLAKE3 Merkle tree engine") for a future partial/resumable
/// download path in `aegis-net`, where a peer may want to verify one
/// chunk against an already-known root before the rest of the file has
/// arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    steps: Vec<ProofStep>,
}

impl MerkleProof {
    /// The proof's steps, ordered from the leaf upward to the root.
    pub fn steps(&self) -> &[ProofStep] {
        &self.steps
    }
}

/// A BLAKE3 Merkle tree over a sequence of leaf hashes (see
/// [`leaf_hash`]), following the RFC 6962 §2.1 `MTH` construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Build a tree from already-computed leaf hashes (see
    /// [`leaf_hash`]), in chunk order.
    pub fn from_leaf_hashes(leaves: Vec<[u8; 32]>) -> Self {
        Self { leaves }
    }

    /// The number of leaves in this tree.
    pub fn leaf_count(&self) -> u32 {
        // A cast, not a checked conversion: the caller-facing invariant
        // (spec Section 5's 1 GiB cap, enforced in `stream`) bounds
        // this to 256 long before it could approach `u32::MAX`.
        self.leaves.len() as u32
    }

    /// The tree's root hash (RFC 6962 `MTH(D[n])`).
    pub fn root(&self) -> [u8; 32] {
        mth(&self.leaves)
    }

    /// Build an [`MerkleProof`] that `leaves[index]` is included in
    /// this tree.
    ///
    /// # Errors
    ///
    /// Returns [`FileError::MerkleIndexOutOfRange`] if `index >=
    /// self.leaf_count()`, including on an empty tree (there is no
    /// valid index into zero leaves).
    pub fn generate_proof(&self, index: u32) -> Result<MerkleProof, FileError> {
        let leaf_count = self.leaf_count();
        if index >= leaf_count {
            return Err(FileError::MerkleIndexOutOfRange { index, leaf_count });
        }
        let steps = path(&self.leaves, index as usize);
        Ok(MerkleProof { steps })
    }
}

/// RFC 6962 §2.1.1 `PATH(m, D[n])`, generalised to also record which
/// side each sibling occupies (RFC 6962's own `PATH` only lists sibling
/// hashes; [`verify_inclusion`] needs the side too, since — unlike
/// `PATH`'s paired verification algorithm — it does not re-derive `(m,
/// n)` by recursion, only replays `node_hash` calls in order).
fn path(leaves: &[[u8; 32]], m: usize) -> Vec<ProofStep> {
    match leaves.len() {
        // RFC 6962 §2.1.1: "PATH(0, {d(0)}) = {}" — a single-leaf
        // (sub)tree needs no sibling to prove membership; its own hash
        // already is the root at that level.
        1 => Vec::new(),
        n => {
            let k = largest_power_of_two_less_than(n);
            if m < k {
                let mut steps = path(&leaves[..k], m);
                steps.push(ProofStep {
                    sibling_hash: mth(&leaves[k..]),
                    sibling_is_right: true,
                });
                steps
            } else {
                let mut steps = path(&leaves[k..], m - k);
                steps.push(ProofStep {
                    sibling_hash: mth(&leaves[..k]),
                    sibling_is_right: false,
                });
                steps
            }
        }
    }
}

/// Verify a [`MerkleProof`]: that `leaf` is included, at the position
/// implied by the proof, in a tree whose root is `root`.
///
/// The index itself is not a parameter — it is implicit in the
/// left/right sequence recorded in `proof`, exactly as it would be for
/// the caller reconstructing position from the audit path alone (a
/// remote peer verifying inclusion typically already knows which chunk
/// index it asked for and is not re-deriving it from the proof, but
/// the proof does not need to carry it as a separate value for
/// verification to be sound).
pub fn verify_inclusion(leaf: &[u8; 32], proof: &MerkleProof, root: &[u8; 32]) -> bool {
    let mut current = *leaf;
    for step in &proof.steps {
        current = if step.sibling_is_right {
            node_hash(&current, &step.sibling_hash)
        } else {
            node_hash(&step.sibling_hash, &current)
        };
    }
    current == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves_from_bytes(chunks: &[&[u8]]) -> Vec<[u8; 32]> {
        chunks.iter().map(|c| leaf_hash(c)).collect()
    }

    #[test]
    fn empty_tree_root_is_the_hash_of_the_empty_string() {
        let tree = MerkleTree::from_leaf_hashes(vec![]);
        assert_eq!(tree.root(), *blake3::hash(&[]).as_bytes());
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn single_leaf_root_is_the_leaf_hash_itself() {
        let leaf = leaf_hash(b"only chunk");
        let tree = MerkleTree::from_leaf_hashes(vec![leaf]);
        assert_eq!(tree.root(), leaf);
    }

    #[test]
    fn leaf_hash_is_domain_separated_from_plain_blake3() {
        let chunk = b"chunk contents";
        assert_ne!(
            leaf_hash(chunk),
            *blake3::hash(chunk).as_bytes(),
            "leaf hash must use the 0x00 prefix, not be a plain BLAKE3 hash",
        );
    }

    #[test]
    fn two_leaf_root_matches_hand_computed_node_hash() {
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        let tree = MerkleTree::from_leaf_hashes(vec![a, b]);
        let expected = node_hash(&a, &b);
        assert_eq!(tree.root(), expected);
    }

    /// n=3 exercises the actual split rule: k = largest power of two <
    /// 3 = 2, so `MTH(D[3]) = Node(MTH(D[0:2]), MTH(D[2:3]))` — a
    /// *lopsided* split (a two-leaf subtree on the left, one leaf on
    /// the right), not a naive "pair (0,1), leave 2 unpaired" scheme.
    #[test]
    fn three_leaf_root_uses_the_lopsided_power_of_two_split() {
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        let c = leaf_hash(b"c");
        let tree = MerkleTree::from_leaf_hashes(vec![a, b, c]);
        let left_subtree = node_hash(&a, &b);
        let expected = node_hash(&left_subtree, &c);
        assert_eq!(tree.root(), expected);
    }

    /// Pins that this implementation does not fall back to the weaker,
    /// non-RFC-6962 scheme of duplicating an unpaired last leaf (see
    /// this module's doc comment for why that scheme is a known
    /// second-preimage weakness). If it did, `MTH(D[3])` would equal
    /// `Node(Node(a,b), Node(c,c))` instead of the true
    /// `Node(Node(a,b), c)` computed above — the two are different
    /// whenever `c != Node(c,c)` (true for any BLAKE3 output, since a
    /// hash never equals its own domain-separated combination with
    /// itself), so this test would fail if the split rule
    /// were ever accidentally "simplified" to leaf duplication.
    #[test]
    fn naive_last_node_duplication_gives_a_different_root_than_rfc6962() {
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        let c = leaf_hash(b"c");
        let tree = MerkleTree::from_leaf_hashes(vec![a, b, c]);

        let naive_duplicated_root = node_hash(&node_hash(&a, &b), &node_hash(&c, &c));
        assert_ne!(tree.root(), naive_duplicated_root);
    }

    #[test]
    fn root_is_order_sensitive() {
        let forward = MerkleTree::from_leaf_hashes(leaves_from_bytes(&[b"a", b"b", b"c", b"d"]));
        let swapped = MerkleTree::from_leaf_hashes(leaves_from_bytes(&[b"b", b"a", b"c", b"d"]));
        assert_ne!(forward.root(), swapped.root());
    }

    #[test]
    fn root_is_content_sensitive() {
        let original = MerkleTree::from_leaf_hashes(leaves_from_bytes(&[b"a", b"b", b"c"]));
        let tampered = MerkleTree::from_leaf_hashes(leaves_from_bytes(&[b"a", b"B", b"c"]));
        assert_ne!(original.root(), tampered.root());
    }

    #[test]
    fn generate_proof_rejects_out_of_range_index() {
        let tree = MerkleTree::from_leaf_hashes(leaves_from_bytes(&[b"a", b"b"]));
        let err = tree.generate_proof(2).unwrap_err();
        assert!(matches!(
            err,
            FileError::MerkleIndexOutOfRange {
                index: 2,
                leaf_count: 2
            }
        ));
    }

    #[test]
    fn generate_proof_on_empty_tree_is_always_out_of_range() {
        let tree = MerkleTree::from_leaf_hashes(vec![]);
        assert!(tree.generate_proof(0).is_err());
    }

    /// Every index of every tree size from 1 to 32 leaves round-trips:
    /// the proof for `leaves[i]` verifies against the tree's true root.
    /// Covers the single-leaf base case, every parity, and several
    /// non-power-of-two sizes where the lopsided split matters.
    #[test]
    fn every_index_proves_inclusion_for_a_range_of_tree_sizes() {
        for n in 1..=32usize {
            let chunk_bytes: Vec<Vec<u8>> =
                (0..n).map(|i| format!("chunk-{i}").into_bytes()).collect();
            let leaves: Vec<[u8; 32]> = chunk_bytes.iter().map(|c| leaf_hash(c)).collect();
            let tree = MerkleTree::from_leaf_hashes(leaves.clone());
            let root = tree.root();
            for (i, leaf) in leaves.iter().enumerate() {
                let proof = tree
                    .generate_proof(i as u32)
                    .unwrap_or_else(|e| panic!("generate_proof failed for n={n}, i={i}: {e}"));
                assert!(
                    verify_inclusion(leaf, &proof, &root),
                    "inclusion proof failed to verify for n={n}, i={i}",
                );
            }
        }
    }

    #[test]
    fn tampered_leaf_fails_inclusion_proof() {
        let leaves = leaves_from_bytes(&[b"a", b"b", b"c", b"d", b"e"]);
        let tree = MerkleTree::from_leaf_hashes(leaves.clone());
        let root = tree.root();
        let proof = tree.generate_proof(2).unwrap();
        let wrong_leaf = leaf_hash(b"not-c");
        assert!(!verify_inclusion(&wrong_leaf, &proof, &root));
        // Sanity: the real leaf still verifies against the same proof.
        assert!(verify_inclusion(&leaves[2], &proof, &root));
    }

    #[test]
    fn tampered_proof_step_fails_inclusion_proof() {
        let leaves = leaves_from_bytes(&[b"a", b"b", b"c", b"d", b"e"]);
        let tree = MerkleTree::from_leaf_hashes(leaves.clone());
        let root = tree.root();
        let mut proof = tree.generate_proof(2).unwrap();
        // Flip a byte in the first sibling hash recorded in the proof.
        proof.steps[0].sibling_hash[0] ^= 0xFF;
        assert!(!verify_inclusion(&leaves[2], &proof, &root));
    }

    #[test]
    fn proof_against_the_wrong_root_fails() {
        let leaves_a = leaves_from_bytes(&[b"a", b"b", b"c"]);
        let leaves_b = leaves_from_bytes(&[b"x", b"y", b"z"]);
        let tree_a = MerkleTree::from_leaf_hashes(leaves_a.clone());
        let tree_b = MerkleTree::from_leaf_hashes(leaves_b);
        let proof = tree_a.generate_proof(1).unwrap();
        assert!(!verify_inclusion(&leaves_a[1], &proof, &tree_b.root()));
    }

    #[test]
    fn root_is_deterministic() {
        let leaves = leaves_from_bytes(&[b"a", b"b", b"c", b"d", b"e", b"f", b"g"]);
        let tree1 = MerkleTree::from_leaf_hashes(leaves.clone());
        let tree2 = MerkleTree::from_leaf_hashes(leaves);
        assert_eq!(tree1.root(), tree2.root());
    }

    /// The spec Section 5 boundary: a 1 GiB file at 4 MiB chunks is
    /// exactly 256 leaves. Exercises the tree at that exact size
    /// (cheaply — only 32-byte leaf hashes, not real chunk data) to
    /// confirm proof generation/verification and the root computation
    /// do not assume a power-of-two-friendly size (256 *is* a power of
    /// two, so this also specifically covers the perfectly-balanced
    /// case, complementing the lopsided-split tests above).
    #[test]
    fn handles_the_256_leaf_boundary() {
        let leaves: Vec<[u8; 32]> = (0..256u32).map(|i| leaf_hash(&i.to_be_bytes())).collect();
        let tree = MerkleTree::from_leaf_hashes(leaves.clone());
        assert_eq!(tree.leaf_count(), 256);
        let root = tree.root();
        let proof = tree.generate_proof(255).unwrap();
        assert!(verify_inclusion(&leaves[255], &proof, &root));
        let proof0 = tree.generate_proof(0).unwrap();
        assert!(verify_inclusion(&leaves[0], &proof0, &root));
    }
}
