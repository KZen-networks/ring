use super::{Curve, ELEM_MAX_BYTES, SEED_MAX_BYTES};
use crate::{cpu, error, rand};
use crate::ec::suite_b::{PrivateKeyOps, PublicKeyOps, Point};
use crate::ec::suite_b::public_key::parse_uncompressed_point;
use crate::ec::suite_b::private_key::{big_endian_affine_from_jacobian, scalar_from_big_endian_bytes};
use std::fmt;
use hex_slice::AsHex;
use std::println;

pub struct KeyPair {
    seed: Seed,
    public_key: PublicKey,
}

impl KeyPair {
    pub fn derive(seed: Seed) -> Result<Self, error::Unspecified> {
        let public_key = seed.compute_public_key()?;
        Ok(Self { seed, public_key })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    pub fn split(self) -> (Seed, PublicKey) {
        (self.seed, self.public_key)
    }
}

#[derive(Copy, Clone)]
pub struct Seed {
    bytes: [u8; SEED_MAX_BYTES],
    curve: &'static Curve,
    pub(crate) cpu_features: cpu::Features,
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Seed {{ bytes: {:x} }}", self.bytes[..self.curve.elem_scalar_seed_len].plain_hex(false))
    }
}

impl fmt::Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}", self.bytes[..self.curve.elem_scalar_seed_len].plain_hex(false))
    }
}

impl Seed {
    pub(crate) fn generate(
        curve: &'static Curve,
        rng: &dyn rand::SecureRandom,
        cpu_features: cpu::Features,
    ) -> Result<Self, error::Unspecified> {
        let mut r = Self {
            bytes: [0u8; SEED_MAX_BYTES],
            curve,
            cpu_features,
        };
        (curve.generate_private_key)(rng, &mut r.bytes[..curve.elem_scalar_seed_len])?;
        Ok(r)
    }

    pub fn from_bytes(
        curve: &'static Curve,
        bytes: untrusted::Input,
        cpu_features: cpu::Features,
    ) -> Result<Seed, error::Unspecified> {
        let bytes = bytes.as_slice_less_safe();
        if curve.elem_scalar_seed_len != bytes.len() {
            return Err(error::Unspecified);
        }
        (curve.check_private_key_bytes)(bytes)?;
        let mut r = Self {
            bytes: [0; SEED_MAX_BYTES],
            curve,
            cpu_features,
        };
        r.bytes[..curve.elem_scalar_seed_len].copy_from_slice(bytes);
        Ok(r)
    }

    pub fn bytes_less_safe(&self) -> &[u8] {
        &self.bytes[..self.curve.elem_scalar_seed_len]
    }

    pub fn compute_public_key(&self) -> Result<PublicKey, error::Unspecified> {
        let mut public_key = PublicKey {
            bytes: [0u8; PUBLIC_KEY_MAX_LEN],
            len: self.curve.public_key_len,
        };
        (self.curve.public_from_private)(&mut public_key.bytes[..public_key.len], self)?;
        Ok(public_key)
    }
}

#[derive(Copy, Clone)]
pub struct PublicKey {
    bytes: [u8; PUBLIC_KEY_MAX_LEN],
    len: usize,
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey {{ bytes: {:x}, len: {} }}", self.bytes[..self.len].as_hex(), self.len)
    }
}

impl PublicKey {

    pub fn new(bytes_uncompressed: &[u8], ops: &PublicKeyOps) -> Result<Self, error::Unspecified> {
        match parse_uncompressed_point(ops, untrusted::Input::from(bytes_uncompressed)) {
            Err(error) => Err(error),
            Ok(_) => {
                let mut bytes = [0; PUBLIC_KEY_MAX_LEN];
                bytes[..bytes_uncompressed.len()].clone_from_slice(bytes_uncompressed);
                Ok(PublicKey {
                    bytes,
                    len: bytes_uncompressed.len(),
                })
            }
        }
    }

    pub fn serialize_uncompressed(&self) -> [u8; PUBLIC_KEY_MAX_LEN] {
        self.bytes
    }

    pub fn add_point(&self, curve: &'static Curve, other: &PublicKey, priv_ops: &PrivateKeyOps, pub_ops: &PublicKeyOps) -> Result<Self, error::Unspecified> {
        let self_point = self.to_point(curve, priv_ops, pub_ops)?;
        let other_point = other.to_point(curve, priv_ops, pub_ops)?;
        let sum_point = pub_ops.common.point_sum(&self_point, &other_point);
        Self::from_point(curve, priv_ops, &sum_point, self.len)
    }

    fn to_point(&self, curve: &'static Curve, priv_ops: &PrivateKeyOps, pub_ops: &PublicKeyOps) -> Result<Point, error::Unspecified> {
        // we're multiplying self by the scalar 1, to get a jacobian encoded Point
        let elems = parse_uncompressed_point(pub_ops, untrusted::Input::from(&self.bytes[..self.len]))?;
        let mut one_vec = vec![1u8];
        let mut template = vec![0; curve.elem_scalar_seed_len - 1];
        template.extend_from_slice(&one_vec);
        one_vec = template;

        let one_scalar = scalar_from_big_endian_bytes(priv_ops, &one_vec.as_slice())?;

        Ok(priv_ops.point_mul(&one_scalar, &elems))
    }

    fn from_point(curve: &'static Curve, ops: &PrivateKeyOps, point: &Point, bytes_len: usize) -> Result<Self, error::Unspecified> {
        println!("form_point. bytes_len = {}", bytes_len);
        let elem_len = curve.elem_scalar_seed_len;
        let mut public_out_vec = vec![0u8; elem_len * 2];
        let mut public_out: &mut [u8] = public_out_vec.as_mut();
        let (x_out, y_out) = (&mut public_out).split_at_mut(elem_len);
        big_endian_affine_from_jacobian(ops, Some(x_out), Some(y_out), &point)?;

        let mut bytes = [0u8; PUBLIC_KEY_MAX_LEN];
        bytes[0] = 4;  // Uncompressed encoding
        bytes[1..(elem_len + 1)].clone_from_slice(&public_out[0..elem_len]);
        bytes[(elem_len + 1)..bytes_len].clone_from_slice(&public_out[elem_len..(2 * elem_len)]);

        Ok(PublicKey {
            bytes,
            len: bytes_len,
        })
    }
}

/// The maximum length, in bytes, of an encoded public key.
pub const PUBLIC_KEY_MAX_LEN: usize = 1 + (2 * ELEM_MAX_BYTES);
