extern crate curve25519_dalek;
extern crate rand;
extern crate sha2;

use sha2::{Digest, Sha512};
use rand::{Rng, CryptoRng};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{RistrettoPoint},
    scalar::Scalar,
    traits::Identity
};
use std::ops::{Deref, Neg};

pub struct KeyPair {
  private: Scalar,
  public:  RistrettoPoint,
}

impl KeyPair {
  pub fn new<T: Rng + CryptoRng>(rng: &mut T) -> Self {
    let private = Scalar::random(rng);
    let public = private * RISTRETTO_BASEPOINT_POINT;

    KeyPair { private, public }
  }
}

#[derive(Clone,Debug,PartialEq)]
pub struct Signature {
  s: Scalar,
  e: Scalar,
}

// schnorr signature
pub fn sign<T: Rng + CryptoRng>(rng: &mut T, private_key: &Scalar, message: &[u8], next_data: Option<&[u8]>)
  -> Signature {

  let k = Scalar::random(rng);
  let r = k * RISTRETTO_BASEPOINT_POINT;

  let mut h = Sha512::new();
  h.input(r.compress().as_bytes());
  h.input(message);
  if let Some(data) = next_data {
    h.input(data);
  }
  let e = Scalar::from_hash(h);

  let s = k - private_key * e;

  Signature { s, e }
}

pub fn verify(public_key: &RistrettoPoint, message: &[u8], next_data: Option<&[u8]>, signature: &Signature)
  -> bool {

  let r = (signature.s * RISTRETTO_BASEPOINT_POINT) + (signature.e * public_key);
  let mut h = Sha512::new();
  h.input(r.compress().as_bytes());
  h.input(message);
  if let Some(data) = next_data {
    h.input(data);
  }
  let e = Scalar::from_hash(h);

  e == signature.e
}

pub struct Token {
  pub messages: Vec<Vec<u8>>,
  pub keys: Vec<RistrettoPoint>,
  pub signatures: Vec<Signature>,
  pub next_key: Scalar,
}

impl Token {
  pub fn new<T: Rng + CryptoRng>(rng: &mut T, keypair: &KeyPair, message: &[u8]) -> Self {
    let next_key = Scalar::random(rng);
    let next_public = next_key * RISTRETTO_BASEPOINT_POINT;

    let signature = sign(rng, &keypair.private, message, Some(next_public.compress().as_bytes()));

    Token {
      messages: vec![message.to_owned()],
      keys: vec![keypair.public],
      signatures: vec![signature],
      next_key,
    }
  }

  pub fn append<T: Rng + CryptoRng>(&self, rng: &mut T, message: &[u8]) -> Self {
    let next_key = Scalar::random(rng);
    let next_public = next_key * RISTRETTO_BASEPOINT_POINT;

    let signature = sign(rng, &self.next_key, message, Some(next_public.compress().as_bytes()));

    let mut t = Token {
      messages: self.messages.clone(),
      keys: self.keys.clone(),
      signatures: self.signatures.clone(),
      next_key,
    };

    let current_public = self.next_key * RISTRETTO_BASEPOINT_POINT;

    t.messages.push(message.to_owned());
    t.keys.push(current_public);
    t.signatures.push(signature);

    t
  }

  pub fn verify(&self) -> bool {
    assert_eq!(self.messages.len(), self.keys.len());
    assert_eq!(self.messages.len(), self.signatures.len());

    let mut keys = self.keys.clone();
    keys.push(self.next_key * RISTRETTO_BASEPOINT_POINT);

    for i in 0..self.messages.len() {
      if !verify(&keys[i], &self.messages[i], Some(keys[i+1].compress().as_bytes()), &self.signatures[i]) {
        println!("error verifying signature {}", i);
        return false;
      } else {
        println!("signature {} verified", i);
      }
    }

    true
  }

  pub fn challenge<T: Rng + CryptoRng>(&self, rng: &mut T, challenge: &[u8]) -> ChallengeToken {
    let next_public = self.next_key * RISTRETTO_BASEPOINT_POINT;
    let mut h = Sha512::new();
    for i in 0..self.messages.len() {
      h.input(&self.messages[i]);
      h.input(self.keys[i].compress().as_bytes());
      h.input(self.signatures[i].s.as_bytes());
      h.input(self.signatures[i].e.as_bytes());
    }
    h.input(next_public.compress().as_bytes());

    // maybe we should hash the whole message instead of just the last signature
    let signature = sign(rng, &self.next_key, challenge, Some(h.result().as_slice()));

    ChallengeToken {
      messages: self.messages.clone(),
      keys: self.keys.clone(),
      signatures: self.signatures.clone(),
      challenge: Vec::from(challenge),
      response: signature,
      next_public,
    }
  }
}

pub struct ChallengeToken {
  pub messages: Vec<Vec<u8>>,
  pub keys: Vec<RistrettoPoint>,
  pub signatures: Vec<Signature>,
  pub challenge: Vec<u8>,
  pub response: Signature,
  pub next_public: RistrettoPoint,
}

impl ChallengeToken {
  pub fn verify(&self) -> bool {
    let mut h = Sha512::new();
    for i in 0..self.messages.len() {
      h.input(&self.messages[i]);
      h.input(self.keys[i].compress().as_bytes());
      h.input(self.signatures[i].s.as_bytes());
      h.input(self.signatures[i].e.as_bytes());
    }
    h.input(self.next_public.compress().as_bytes());

    if !verify(&self.next_public, &self.challenge, Some(h.result().as_slice()), &self.response) {
      println!("error verifying challenge response");
      return false;
    }

    assert_eq!(self.messages.len(), self.keys.len());
    assert_eq!(self.messages.len(), self.signatures.len());

    let mut keys = self.keys.clone();
    keys.push(self.next_public);

    for i in 0..self.messages.len() {
      if !verify(&keys[i], &self.messages[i], Some(keys[i+1].compress().as_bytes()), &self.signatures[i]) {
        println!("error verifying signature {}", i);
        return false;
      }
    }

    true
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use rand::{OsRng,SeedableRng,StdRng};

  #[test]
  fn three_messages() {
    //let mut rng: OsRng = OsRng::new().unwrap();
    //keep the same values in tests
    let mut rng: StdRng = SeedableRng::seed_from_u64(0);

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&mut rng, &keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");
    assert!(token1.challenge(&mut rng, &b"pouet"[..]).verify(), "cannot verify first challenge token");

    println!("will derive a second token");

    let message2 = b"world";

    let token2 = token1.append(&mut rng, &message2[..]);

    assert!(token2.verify(), "cannot verify second token");
    assert!(token2.challenge(&mut rng, &b"hi"[..]).verify(), "cannot verify second challenge token");

    println!("will derive a third token");

    let message3 = b"!!!";

    let token3 = token2.append(&mut rng, &message3[..]);

    assert!(token3.verify(), "cannot verify third token");
    assert!(token3.challenge(&mut rng, &b"test"[..]).verify(), "cannot verify third challenge token");
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

    let mut token2 = token1.append(&mut rng, &message2[..]);

    token2.messages[1] = Vec::from(&b"you"[..]);

    assert!(!token2.verify(), "second token should not be valid");

    println!("will derive a third token");

    let message3 = b"!!!";

    let token3 = token2.append(&mut rng, &message3[..]);

    assert!(!token3.verify(), "third token should not be valid");
  }
}
