use super::{Curve, ELEM_MAX_BYTES, SEED_MAX_BYTES};
use crate::{cpu, error, rand};
use crate::ec::suite_b::{PrivateKeyOps, PublicKeyOps, Point, elem_parse_big_endian_fixed_consttime, CommonOps};
use crate::ec::suite_b::public_key::parse_uncompressed_point;
use crate::ec::suite_b::private_key::{big_endian_affine_from_jacobian, scalar_from_big_endian_bytes, private_key_as_scalar};
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

impl Seed {
    pub fn zero(curve: &'static Curve, cpu_features: cpu::Features) -> Self {
        Seed {
            bytes: [0u8; SEED_MAX_BYTES],
            curve,
            cpu_features,
        }
    }

    pub fn is_zero(&self, ops: &CommonOps) -> bool {
        let elem = elem_parse_big_endian_fixed_consttime(
            ops,
            untrusted::Input::from(self.bytes_less_safe()))
            .unwrap();
        ops.is_zero(&elem)
    }
}

impl PartialEq for Seed {
    fn eq(&self, other: &Seed) -> bool {
        if self.curve.id != self.curve.id {
            return false;
        }

        for i in 0..self.curve.elem_scalar_seed_len {
            if self.bytes[i] != other.bytes[i] {
                return false;
            }
        }

        return true;
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Seed {{ bytes: {:x} }}", self.bytes_less_safe().plain_hex(false))
    }
}

impl fmt::Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}", self.bytes_less_safe().plain_hex(false))
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
        (curve.generate_private_key)(rng, &mut r.bytes[..r.curve.elem_scalar_seed_len])?;
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
        r.bytes[..r.curve.elem_scalar_seed_len].copy_from_slice(bytes);
        Ok(r)
    }

    pub fn bytes_less_safe(&self) -> &[u8] {
        &self.bytes[..self.curve.elem_scalar_seed_len]
    }

    pub fn compute_public_key_incl_zero(&self, ops: &CommonOps) -> Result<PublicKey, error::Unspecified> {
        // TODO make constant time
        if Seed::is_zero(self, ops) {
            let mut bytes = [0; PUBLIC_KEY_MAX_LEN];
            bytes[0] = 4u8; // uncompresssed encoding
            return Ok(PublicKey {
                bytes,
                len: self.curve.public_key_len,
            })
        }

        self.compute_public_key()
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

const POINT_AT_INFINITY_BYTES: [u8; PUBLIC_KEY_MAX_LEN] = [
    4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0
];

#[derive(Copy, Clone)]
pub struct PublicKey {
    bytes: [u8; PUBLIC_KEY_MAX_LEN],
    len: usize,
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        if self.len != other.len {
            return false;
        }

        for i in 0..self.len {
            if self.bytes[i] != other.bytes[i] {
                return false;
            }
        }

        return true;
    }
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
            Err(error) => {
                if Self::_is_point_at_infinity(bytes_uncompressed, bytes_uncompressed.len()) {
                    Self::_new(bytes_uncompressed)
                } else {
                    Err(error)
                }
            },
            Ok(_) => Self::_new(bytes_uncompressed)
        }
    }

    fn _new(bytes_uncompressed: &[u8]) -> Result<Self, error::Unspecified> {
        let mut bytes = [0; PUBLIC_KEY_MAX_LEN];
        bytes[..bytes_uncompressed.len()].clone_from_slice(bytes_uncompressed);
        Ok(PublicKey {
            bytes,
            len: bytes_uncompressed.len(),
        })
    }

    fn point_at_infinity(len: usize) -> Result<Self, error::Unspecified> {
        Ok(PublicKey {
            bytes: POINT_AT_INFINITY_BYTES,
            len,
        })
    }

    pub fn is_point_at_infinity(&self) -> bool {
        Self::_is_point_at_infinity(&self.bytes, self.len)
    }

    // TODO: make more efficient by bitwise opeartions
    fn _is_point_at_infinity(bytes: &[u8], len: usize) -> bool {
        if bytes[0] != 4u8 {
            return false;
        }

        for i in 1..len {
            if bytes[i] != 0u8 {
                return false;
            }
        }

        true
    }

    pub fn serialize_uncompressed(&self) -> [u8; PUBLIC_KEY_MAX_LEN] {
        self.bytes
    }

    pub fn scalar_mul(&self, seed: &Seed, priv_ops: &PrivateKeyOps, pub_ops: &PublicKeyOps) -> Result<Self, error::Unspecified> {
        match parse_uncompressed_point(pub_ops, untrusted::Input::from(&self.bytes[..self.len])) {
            Err(error) => {
                if self.is_point_at_infinity() {
                    Ok(*self)
                } else {
                    Err(error)
                }
            },
            Ok(public_key) => {
                // TODO consider constant time
                if seed.is_zero(priv_ops.common) {
                    return Self::point_at_infinity(self.len);
                }
                let scalar = private_key_as_scalar(priv_ops, seed);
                let point = priv_ops.point_mul(&scalar, &public_key);

                let elem_len = (self.len - 1) / 2;
                let mut public_out_vec = vec![0u8; elem_len * 2];
                let mut public_out: &mut [u8] = public_out_vec.as_mut();
                let (x_out, y_out) = (&mut public_out).split_at_mut(elem_len);
                big_endian_affine_from_jacobian(priv_ops, Some(x_out), Some(y_out), &point)?;

                let mut bytes = [0u8; PUBLIC_KEY_MAX_LEN];
                bytes[0] = 4;  // Uncompressed encoding
                bytes[1..(elem_len + 1)].clone_from_slice(&public_out[0..elem_len]);
                bytes[(elem_len + 1)..self.len].clone_from_slice(&public_out[elem_len..(2 * elem_len)]);

                Ok(PublicKey {
                    bytes,
                    len: self.len,
                })
            }
        }
    }

    pub fn add_point(&self, curve: &'static Curve, other: &PublicKey, priv_ops: &PrivateKeyOps, pub_ops: &PublicKeyOps) -> Result<Self, error::Unspecified> {
        let self_point = self.to_point(curve, priv_ops, pub_ops)?;
        let other_point = other.to_point(curve, priv_ops, pub_ops)?;
        let sum_point = pub_ops.common.point_sum(&self_point, &other_point);
        Self::from_point(curve, priv_ops, &sum_point, self.len)
    }

    fn to_point(&self, curve: &'static Curve, priv_ops: &PrivateKeyOps, pub_ops: &PublicKeyOps) -> Result<Point, error::Unspecified> {
        match parse_uncompressed_point(pub_ops, untrusted::Input::from(&self.bytes[..self.len])) {
            Err(e) => {
                if self.is_point_at_infinity() {
                    Ok(Point::new_at_infinity())
                } else {
                    Err(e)
                }
            },
            Ok(elems) => {
                // we're multiplying self by the scalar 1, to get a jacobian encoded Point
                let mut one_vec = vec![1u8];  // TODO: make a constant
                let mut template = vec![0; curve.elem_scalar_seed_len - 1];
                template.extend_from_slice(&one_vec);
                one_vec = template;

                let one_scalar = scalar_from_big_endian_bytes(priv_ops, &one_vec.as_slice())?;

                Ok(priv_ops.point_mul(&one_scalar, &elems))
            }
        }
    }

    fn from_point(curve: &'static Curve, ops: &PrivateKeyOps, point: &Point, bytes_len: usize) -> Result<Self, error::Unspecified> {
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
