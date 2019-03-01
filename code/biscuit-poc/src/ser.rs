use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Serialize, Deserialize};
use vrf::{KeyPair, TokenSignature};

use super::Block;

#[derive(Clone,Debug,Serialize,Deserialize)]
pub struct SerializedBiscuit {
  pub authority: Vec<u8>,
  pub blocks: Vec<Vec<u8>>,
  pub keys: Vec<RistrettoPoint>,
  pub signature: TokenSignature,
}

impl SerializedBiscuit {
  pub fn from(slice: &[u8], public_key: RistrettoPoint) -> Result<Self, String> {
    let deser: SerializedBiscuit = serde_cbor::from_slice(&slice)
      .map_err(|e| format!("deserialization error: {:?}", e))?;

    if !deser.verify(public_key) {
      return Err(String::from("invalid signature"));
    }

    Ok(deser)
  }

  pub fn to_vec(&self) -> Vec<u8> {
    serde_cbor::to_vec(self).unwrap()
  }

  pub fn new(keypair: &KeyPair, authority: &Block) -> Self {
    let v = serde_cbor::to_vec(authority).unwrap();
    let signature = TokenSignature::new(keypair, &v);

    SerializedBiscuit {
      authority: v,
      blocks: vec![],
      keys: vec![keypair.public],
      signature
    }
  }

  pub fn append(&self, keypair: &KeyPair, block: &Block) -> Self {
    let v = serde_cbor::to_vec(block).unwrap();

    let mut blocks = Vec::new();
    blocks.push(self.authority.clone());
    blocks.extend(self.blocks.iter().cloned());

    let signature = self.signature.sign(&self.keys, &blocks, keypair, &v);

    let mut t = SerializedBiscuit {
      authority: self.authority.clone(),
      blocks: self.blocks.clone(),
      keys: self.keys.clone(),
      signature
    };

    t.blocks.push(v);
    t.keys.push(keypair.public);

    t
  }

  pub fn verify(&self, public: RistrettoPoint) -> bool {
    if self.keys.is_empty() {
      return false;
    }
    if self.keys[0] != public {
      return false;
    }

    let mut blocks = Vec::new();
    blocks.push(self.authority.clone());
    blocks.extend(self.blocks.iter().cloned());

    self.signature.verify(&self.keys, &blocks)
  }
}

