use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use super::Biscuit;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone,Debug,Serialize,Deserialize)]
pub struct SealedBiscuit {
  pub authority: Vec<u8>,
  pub blocks:    Vec<Vec<u8>>,
  pub signature: Vec<u8>,
}

impl SealedBiscuit {
  pub fn from_token(token: &Biscuit, secret: &[u8]) -> Self {
    let authority = serde_cbor::ser::to_vec_packed(&token.authority).unwrap();
    let blocks = token.blocks.iter().map(|b| serde_cbor::ser::to_vec_packed(b).unwrap()).collect::<Vec<_>>();

    let mut mac = HmacSha256::new_varkey(secret).unwrap();
    mac.input(&authority);
    for block in blocks.iter() {
      mac.input(&block);
    }

    let signature: Vec<u8> = mac.result().code().to_vec();

    SealedBiscuit { authority, blocks, signature }
  }

  pub fn from_slice(slice: &[u8], secret: &[u8]) ->Result<Self, String> {
  let deser: SealedBiscuit = serde_cbor::from_slice(slice)
      .map_err(|e| format!("deserialization error: {:?}", e))?;

    let mut mac = HmacSha256::new_varkey(secret).unwrap();
    mac.input(&deser.authority);
    for block in deser.blocks.iter() {
      mac.input(&block);
    }

    mac.verify(&deser.signature).map_err(|e| format!("invalid signature: {:?}", e))?;

    Ok(deser)
  }

  pub fn to_vec(&self) -> Vec<u8> {
    serde_cbor::ser::to_vec_packed(self).unwrap()
  }
}
