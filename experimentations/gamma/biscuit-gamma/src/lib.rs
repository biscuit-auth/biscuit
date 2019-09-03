#![allow(non_snake_case)]

extern crate curve25519_dalek;
extern crate rand;
extern crate sha2;
extern crate hmac;
extern crate serde;

use sha2::{Digest, Sha512};
use hmac::{Hmac, Mac};
use rand::prelude::*;
use serde::{Serialize, Deserialize};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{RistrettoPoint},
    scalar::Scalar,
    traits::Identity
};
use std::ops::{Deref, Neg};

type HmacSha512 = Hmac<Sha512>;


pub struct KeyPair {
  private: Scalar,
  pub public:  RistrettoPoint,
}

impl KeyPair {
  pub fn new<T: Rng + CryptoRng>(rng: &mut T) -> Self {
    let private = Scalar::random(rng);
    let public = private * RISTRETTO_BASEPOINT_POINT;

    KeyPair { private, public }
  }

  pub fn sign<T: Rng + CryptoRng>(&self, rng: &mut T, message: &[u8]) -> (Scalar, Scalar) {
    let r = Scalar::random(rng);
    let A = r * RISTRETTO_BASEPOINT_POINT;
    let d = ECVRF_hash_points(&[A]);
    // FIXME: maybe there's a simpler hashing process
    let e = ECVRF_hash_points(&[self.public, ECVRF_hash_to_curve(RISTRETTO_BASEPOINT_POINT, message)]);
    let z = r*d - e*self.private;
    (d, z)
  }
}

pub fn verify(public: &RistrettoPoint, message: &[u8], signature: &(Scalar, Scalar)) -> bool {
  let (d, z) = signature;
  let e = ECVRF_hash_points(&[*public, ECVRF_hash_to_curve(RISTRETTO_BASEPOINT_POINT, message)]);
  let d_inv = d.invert();
  let A = z * d_inv * RISTRETTO_BASEPOINT_POINT + e * d_inv * public;

  ECVRF_hash_points(&[A]) == *d
}

pub struct Token {
  pub messages: Vec<Vec<u8>>,
  pub keys: Vec<RistrettoPoint>,
  pub signature: TokenSignature,
}

impl Token {
  pub fn new<T: Rng + CryptoRng>(rng: &mut T, keypair: &KeyPair, message: &[u8]) -> Self {
    let signature = TokenSignature::new(rng, keypair, message);

    Token {
      messages: vec![message.to_owned()],
      keys: vec![keypair.public],
      signature
    }
  }

  pub fn append<T: Rng + CryptoRng>(&self, rng: &mut T, keypair: &KeyPair, message: &[u8]) -> Self {
    let signature = self.signature.sign(rng, &self.keys, &self.messages, keypair, message);

    let mut t = Token {
      messages: self.messages.clone(),
      keys: self.keys.clone(),
      signature
    };

    t.messages.push(message.to_owned());
    t.keys.push(keypair.public);

    t
  }

  pub fn verify(&self) -> bool {
    self.signature.verify(&self.keys, &self.messages)
  }
}

#[derive(Clone,Debug,Serialize,Deserialize)]
pub struct TokenSignature {
  parameters: Vec<RistrettoPoint>,
  z: Scalar
}

impl TokenSignature {
  pub fn new<T: Rng + CryptoRng>(rng: &mut T, keypair: &KeyPair, message: &[u8]) -> Self {
    let r = Scalar::random(rng);
    let A = r * RISTRETTO_BASEPOINT_POINT;
    let d = ECVRF_hash_points(&[A]);
    let e = hash_message(keypair.public, message);
    let z = r*d - e * keypair.private;

    TokenSignature {
      parameters: vec![A],
      z: z,
    }
  }

  pub fn sign<M: Deref<Target=[u8]>, T: Rng + CryptoRng>(&self, rng: &mut T, public_keys: &[RistrettoPoint],
    messages: &[M], keypair: &KeyPair, message: &[u8]) -> Self {
    let r = Scalar::random(rng);
    let A = r * RISTRETTO_BASEPOINT_POINT;
    let d = ECVRF_hash_points(&[A]);
    let e = hash_message(keypair.public, message);
    let z = r*d - e * keypair.private;

    let mut t = TokenSignature {
      parameters: self.parameters.clone(),
      z: self.z + z,
    };

    t.parameters.push(A);
    t
  }

  pub fn verify<M: Deref<Target=[u8]>>(&self, public_keys: &[RistrettoPoint], messages: &[M]) -> bool {
    if !(public_keys.len() == messages.len()
         && public_keys.len() == self.parameters.len()) {
      println!("invalid data");
      return false;
    }

    let zP = self.z * RISTRETTO_BASEPOINT_POINT;
    let eiXi = public_keys.iter().zip(messages).map(|(pubkey, message)| {
      let e = hash_message(*pubkey, message);
      e * pubkey
    }).fold(RistrettoPoint::identity(), |acc, point| acc + point);

    let diAi = self.parameters.iter().map(|A| {
      let d = ECVRF_hash_points(&[*A]);
      d * A
    }).fold(RistrettoPoint::identity(), |acc, point| acc + point);

    let res = zP + eiXi - diAi;

    /*
    println!("verify identity={:?}", RistrettoPoint::identity());
    println!("verify res={:?}", res);
    println!("verify identity={:?}", RistrettoPoint::identity().compress());
    println!("verify res={:?}", res.compress());
    println!("returning: {:?}", RistrettoPoint::identity() == res);
    */

    RistrettoPoint::identity() == res
  }

}

//FIXME: the ECVRF_hash_to_curve1 looks like a hash and pray, but since
// curve25519-dalek already has a hash to curve function, we can reuse it instead?
pub fn ECVRF_hash_to_curve(point: RistrettoPoint, data: &[u8]) -> RistrettoPoint {
  let h = Sha512::new()
    .chain(point.compress().as_bytes())
    .chain(data);

  RistrettoPoint::from_hash(h)
}

//FIXME: is the output value in the right set?
pub fn ECVRF_hash_points(points: &[RistrettoPoint]) -> Scalar {
  let mut h = Sha512::new();
  for point in points.iter() {
    h.input(point.compress().as_bytes());
  }

  Scalar::from_hash(h)
}

pub fn hash_message(point: RistrettoPoint, data: &[u8]) -> Scalar {
  let h = Sha512::new()
    .chain(point.compress().as_bytes())
    .chain(data);

  Scalar::from_hash(h)
}


pub fn add_points(points: &[RistrettoPoint]) -> RistrettoPoint {
  assert!(points.len() > 0);

  if points.len() == 1 {
    points[0]
  } else {
    let mut it = points.iter();
    let first = it.next().unwrap();
    it.fold(*first, |acc, pk| acc + pk)
  }
}

pub fn ECVRF_nonce(sk: Scalar, point: RistrettoPoint) -> Scalar {
  let k = [0u8; 64];
  let v = [1u8; 64];

  let mut mac = HmacSha512::new_varkey(&k[..]).unwrap();
  mac.input(&v[..]);
  mac.input(&[0]);
  mac.input(&sk.as_bytes()[..]);
  mac.input(point.compress().as_bytes());

  let k = mac.result().code();

  let mut mac = HmacSha512::new_varkey(&k[..]).unwrap();
  mac.input(&v[..]);
  mac.input(&[1]);
  mac.input(&sk.as_bytes()[..]);
  mac.input(point.compress().as_bytes());

  let k = mac.result().code();

  // the process in RFC 6979 is a bit ore complex than that
  let mut h = Sha512::new();
  h.input(k);

  Scalar::from_hash(h)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn basic_signature() {
    let mut rng: StdRng = SeedableRng::seed_from_u64(0);

    let message = b"hello world";
    let keypair = KeyPair::new(&mut rng);

    let signature = keypair.sign(&mut rng, message);

    assert!(verify(&keypair.public, message, &signature));

    assert!(!verify(&keypair.public, b"AAAA", &signature));

  }

  #[test]
  fn three_messages() {
    //let mut rng: OsRng = OsRng::new().unwrap();
    //keep the same values in tests
    let mut rng: StdRng = SeedableRng::seed_from_u64(0);

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&mut rng, &keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    println!("will derive a second token");

    let message2 = b"world";
    let keypair2 = KeyPair::new(&mut rng);

    let token2 = token1.append(&mut rng, &keypair2, &message2[..]);

    assert!(token2.verify(), "cannot verify second token");

    println!("will derive a third token");

    let message3 = b"!!!";
    let keypair3 = KeyPair::new(&mut rng);

    let token3 = token2.append(&mut rng, &keypair3, &message3[..]);

    assert!(token3.verify(), "cannot verify third token");
  }

  #[test]
  fn change_message() {
    //let mut rng: OsRng = OsRng::new().unwrap();
    //keep the same values in tests
    let mut rng: StdRng = SeedableRng::seed_from_u64(0);

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&mut rng, &keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    println!("will derive a second token");

    let message2 = b"world";
    let keypair2 = KeyPair::new(&mut rng);

    let mut token2 = token1.append(&mut rng, &keypair2, &message2[..]);

    token2.messages[1] = Vec::from(&b"you"[..]);

    assert!(!token2.verify(), "second token should not be valid");

    println!("will derive a third token");

    let message3 = b"!!!";
    let keypair3 = KeyPair::new(&mut rng);

    let token3 = token2.append(&mut rng, &keypair3, &message3[..]);

    assert!(!token3.verify(), "cannot verify third token");
  }
}
