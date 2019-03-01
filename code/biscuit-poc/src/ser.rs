use rand::prelude::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Serialize, Deserialize};
use vrf::{KeyPair, TokenSignature};

use super::{BiscuitLogic,Block};

#[derive(Clone,Debug,Serialize,Deserialize)]
pub struct SerializedBiscuit {
  pub authority: Vec<u8>,
  pub blocks: Vec<Vec<u8>>,
  pub keys: Vec<RistrettoPoint>,
  pub signature: TokenSignature,
}

impl SerializedBiscuit {
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

  pub fn deserialize_logic(&self) -> Result<BiscuitLogic, String> {
    let authority: Block = serde_cbor::from_slice(&self.authority).map_err(|e| format!("error deserializing authority block: {:?}", e))?;

    if authority.index != 0 {
      return Err(String::from("authority block should have index 0"));
    }

    let mut blocks = vec![];

    let mut index = 1;
    for block in self.blocks.iter() {
      let deser:Block = serde_cbor::from_slice(&block).map_err(|e| format!("error deserializing block: {:?}", e))?;
      if deser.index != index {
        return Err(format!("invalid index {} for block n°{}", deser.index, index));
      }
      blocks.push(deser);

      index += 1;
    }

    Ok(BiscuitLogic::new(authority, blocks))
  }
}

