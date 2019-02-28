#![allow(non_snake_case)]

extern crate curve25519_dalek;
extern crate rand;
extern crate sha2;
extern crate hmac;
extern crate serde;

pub mod second;

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
}

pub struct Token {
  pub messages: Vec<Vec<u8>>,
  pub keys: Vec<RistrettoPoint>,
  pub signature: TokenSignature,
}

impl Token {
  pub fn new(keypair: &KeyPair, message: &[u8]) -> Self {
    let signature = TokenSignature::new(keypair, message);

    Token {
      messages: vec![message.to_owned()],
      keys: vec![keypair.public],
      signature
    }
  }

  pub fn append(&self, keypair: &KeyPair, message: &[u8]) -> Self {
    let signature = self.signature.sign(&self.keys, &self.messages, keypair, message);

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
  gamma: Vec<RistrettoPoint>,
  c: Vec<Scalar>,
  w: RistrettoPoint,
  s: Scalar
}

impl TokenSignature {
  pub fn new(keypair: &KeyPair, message: &[u8]) -> Self {
    let h = ECVRF_hash_to_curve(keypair.public, message);
    let gamma = keypair.private * h;
    let k = ECVRF_nonce(keypair.private, h);
    let c = ECVRF_hash_points(&[h, gamma, k* RISTRETTO_BASEPOINT_POINT, k*h]);
    let s = (k + c * keypair.private).reduce();

    // W = h^(s0 - S) * .. * hn^(sn - S)
    let w = RistrettoPoint::identity();

    TokenSignature {
      gamma: vec![gamma],
      c: vec![c],
      w,
      s
    }
  }

  pub fn sign<M: Deref<Target=[u8]>>(&self, public_keys: &[RistrettoPoint],
    messages: &[M], keypair: &KeyPair, message: &[u8]) -> Self {
    let h = ECVRF_hash_to_curve(keypair.public, message);
    let gamma = keypair.private * h;
    let k = ECVRF_nonce(keypair.private, h);

    let pc = public_keys.iter().zip(self.c.iter()).map(|(p, c)| p*(c.neg())).collect::<Vec<_>>();
    // u = g^(k0 + k1 + ... + kn)
    let u = add_points(&pc)  + (self.s * RISTRETTO_BASEPOINT_POINT) + (k * RISTRETTO_BASEPOINT_POINT);

    let hashes = messages.iter().zip(public_keys.iter()).map(|(m, pk)| ECVRF_hash_to_curve(*pk, m)).collect::<Vec<_>>();
    let hashes_sum = add_points(&hashes);

    // v = h0^k0 * h1^k1 * .. * hn^k^n
    let v = self.gamma.iter().zip(self.c.iter()).fold(self.w, |acc, (gamma, c)| {
      (c.neg() * gamma) + acc
    }) + (self.s * hashes_sum) + (k * h);

    let gammas = add_points(&self.gamma);

    let c = ECVRF_hash_points(&[h, gammas + gamma, u, v]);

    let s = (k + c * keypair.private).reduce();
    let agg_s = (self.s + s).reduce();

    let hs = hashes_sum * s.neg();
    let w = self.w + hs + h * self.s.neg();

    let mut res = TokenSignature {
      gamma: self.gamma.clone(),
      c: self.c.clone(),
      w,
      s: agg_s
    };
    res.gamma.push(gamma);
    res.c.push(c);

    res
  }

  pub fn verify<M: Deref<Target=[u8]>>(&self, public_keys: &[RistrettoPoint], messages: &[M]) -> bool {
    if !(public_keys.len() == messages.len()
         && public_keys.len() == self.gamma.len()
         && public_keys.len() == self.c.len()) {
      println!("invalid data");
      return false;
    }

    let pc = public_keys.iter().zip(self.c.iter()).map(|(p, c)| p*(c.neg())).collect::<Vec<_>>();
    // u = g^(k0 + k1 + ... + kn)
    let u = add_points(&pc) + (self.s *RISTRETTO_BASEPOINT_POINT);

    let hashes = messages.iter().zip(public_keys.iter()).map(|(m, pk)| ECVRF_hash_to_curve(*pk, m)).collect::<Vec<_>>();

    // v = h0^k0 * h1^k1 * .. * hn^k^n
    let v = self.gamma.iter().zip(self.c.iter()).zip(hashes.iter()).fold(self.w, |acc, ((gamma, c), h)| {
      (c.neg() * gamma) + (self.s * h) + acc
    });

    let gammas = add_points(&self.gamma);

    let c = ECVRF_hash_points(&[*hashes.last().unwrap(), gammas, u, v]);

    c == *self.c.last().unwrap()
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
  fn three_messages() {
    //let mut rng: OsRng = OsRng::new().unwrap();
    //keep the same values in tests
    let mut rng: StdRng = SeedableRng::seed_from_u64(0);

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    println!("will derive a second token");

    let message2 = b"world";
    let keypair2 = KeyPair::new(&mut rng);

    let token2 = token1.append(&keypair2, &message2[..]);

    assert!(token2.verify(), "cannot verify second token");

    println!("will derive a third token");

    let message3 = b"!!!";
    let keypair3 = KeyPair::new(&mut rng);

    let token3 = token2.append(&keypair3, &message3[..]);

    assert!(token3.verify(), "cannot verify third token");
  }

  #[test]
  fn change_message() {
    //let mut rng: OsRng = OsRng::new().unwrap();
    //keep the same values in tests
    let mut rng: StdRng = SeedableRng::seed_from_u64(0);

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    println!("will derive a second token");

    let message2 = b"world";
    let keypair2 = KeyPair::new(&mut rng);

    let mut token2 = token1.append(&keypair2, &message2[..]);

    token2.messages[1] = Vec::from(&b"you"[..]);

    assert!(!token2.verify(), "second token should not be valid");

    println!("will derive a third token");

    let message3 = b"!!!";
    let keypair3 = KeyPair::new(&mut rng);

    let token3 = token2.append(&keypair3, &message3[..]);

    assert!(token3.verify(), "cannot verify third token");
  }
}
