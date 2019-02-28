extern crate datalog_with_constraints as datalog;
extern crate biscuit_vrf as vrf;
extern crate rand;
extern crate curve25519_dalek;
extern crate serde;
extern crate serde_cbor;
#[macro_use]
extern crate nom;

use rand::prelude::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Serialize, Deserialize};
use nom::HexDisplay;
use vrf::{KeyPair, TokenSignature};
use datalog::*;

pub fn default_symbol_table() -> SymbolTable {
  let mut syms = SymbolTable::new();
  syms.insert("authority");
  syms.insert("ambient");

  syms
}

pub struct BiscuitLogic {
  authority: Block,
  blocks: Vec<Block>,
}

impl BiscuitLogic {
  pub fn check(&self, mut ambient_facts: Vec<Fact>, mut ambient_rules: Vec<Rule>) -> Result<(), Vec<String>> {
    let mut world = World::new();
    let mut symbols = default_symbol_table();
    symbols.symbols.extend(self.authority.symbols.symbols.iter().cloned());

    let authority_index = symbols.get("authority").unwrap();
    let ambient_index = symbols.get("ambient").unwrap();

    for fact in self.authority.facts.iter().cloned() {
      if fact.0.ids[0] != ID::Symbol(authority_index) {
        return Err(vec![format!("invalid authority fact: {}", symbols.print_fact(&fact))]);
      }

      world.facts.insert(fact);
    }

    // autority caveats are actually rules
    for rule in self.authority.caveats.iter().cloned() {
      world.rules.push(rule);
    }

    world.run();

    if world.facts.iter().find(|fact| fact.0.ids[0] != ID::Symbol(authority_index)).is_some() {
      return Err(vec![String::from("generated authority facts should have the authority context")]);
    }

    //remove authority rules: we cannot create facts anymore in authority scope
    //w.rules.clear();

    for fact in ambient_facts.drain(..) {
      if fact.0.ids[0] != ID::Symbol(ambient_index) {
        return Err(vec![format!("invalid ambient fact: {}", symbols.print_fact(&fact))]);
      }

      world.facts.insert(fact);
    }

    for rule in ambient_rules.iter().cloned() {
      world.rules.push(rule);
    }

    world.run();

    // we only keep the verifier rules
    world.rules = ambient_rules;

    let mut errors = vec![];
    for (i, block) in self.blocks.iter().enumerate() {
      let w = world.clone();
      let syms = symbols.clone();

      match block.check(i, w, syms) {
        Err(mut e) => {
          errors.extend(e.drain(..));
        },
        Ok(_) => {}
      }
    }

    if errors.is_empty() {
      Ok(())
    } else {
      Err(errors)
    }
  }

  pub fn create_block(&self) -> Block {
    let mut symbols = default_symbol_table();
    symbols.symbols.extend(self.authority.symbols.symbols.iter().cloned());

    Block::new((1 + self.blocks.len()) as u32, symbols)
  }

  pub fn adjust_authority_symbols(block: &mut Block) {
    let mut base_symbols = default_symbol_table();

    let new_syms = block.symbols.symbols.split_off(base_symbols.symbols.len());

    block.symbols.symbols = new_syms;
  }

  pub fn adjust_block_symbols(&self, block: &mut Block) {
    let mut base_symbols = default_symbol_table();
    base_symbols.symbols.extend(self.authority.symbols.symbols.iter().cloned());

    let new_syms = block.symbols.symbols.split_off(base_symbols.symbols.len());

    block.symbols.symbols = new_syms;
  }
}

#[derive(Clone,Debug,Serialize,Deserialize)]
pub struct Block {
  pub index: u32,
  pub symbols: SymbolTable,
  pub facts: Vec<Fact>,
  pub caveats: Vec<Rule>,
}

impl Block {
  pub fn new(index: u32, base_symbols: SymbolTable) -> Block {
    Block {
      index,
      symbols: base_symbols,
      facts: vec![],
      caveats: vec![],
    }
  }

  pub fn symbol(&mut self, s: &str) -> ID {
    self.symbols.add(s)
  }

  pub fn check(&self, i: usize, mut world: World, mut symbols: SymbolTable) -> Result<(), Vec<String>> {
    symbols.symbols.extend(self.symbols.symbols.iter().cloned());
    let authority_index = symbols.get("authority").unwrap();
    let ambient_index = symbols.get("ambient").unwrap();

    for fact in self.facts.iter().cloned() {
      if fact.0.ids[0] == ID::Symbol(authority_index) ||
        fact.0.ids[0] == ID::Symbol(ambient_index) {
        return Err(vec![format!("Block {}: invalid fact: {}", i, symbols.print_fact(&fact))]);
      }

      world.facts.insert(fact);
    }

    world.run();

    let mut errors = vec![];
    for (j, caveat) in self.caveats.iter().enumerate() {
      let res = world.query_rule(caveat.clone());
      if res.is_empty() {
        errors.push(format!("Block {}: caveat {} failed: {}", i, j, symbols.print_rule(caveat)));
      }
    }

    if errors.is_empty() {
      Ok(())
    } else {
      Err(errors)
    }
  }
}

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

    Ok(BiscuitLogic { authority, blocks })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn basic() {
    let mut rng: StdRng = SeedableRng::seed_from_u64(0);

    let symbols = default_symbol_table();
    let mut authority_block = Block::new(0, symbols);

    let authority = authority_block.symbols.add("authority");
    let ambient = authority_block.symbols.add("ambient");
    let file1 = authority_block.symbols.add("file1");
    let file2 = authority_block.symbols.add("file2");
    let read = authority_block.symbols.add("read");
    let write = authority_block.symbols.add("write");
    let right = authority_block.symbols.insert("right");
    let resource = authority_block.symbols.insert("resource");
    let operation = authority_block.symbols.insert("operation");
    let caveat1 = authority_block.symbols.insert("caveat1");
    let caveat2 = authority_block.symbols.insert("caveat2");

    authority_block.facts = vec![
      fact(right, &[&authority, &file1, &read]),
      fact(right, &[&authority, &file2, &read]),
      fact(right, &[&authority, &file1, &write]),
    ];

    BiscuitLogic::adjust_authority_symbols(&mut authority_block);

    let root = KeyPair::new(&mut rng);

    let biscuit1 = SerializedBiscuit::new(&root, &authority_block);
    let serialized1 = serde_cbor::to_vec(&biscuit1).unwrap();

    println!("generated biscuit token: {} bytes:\n{}", serialized1.len(), serialized1.to_hex(16));

    let biscuit1_deser: SerializedBiscuit = serde_cbor::from_slice(&serialized1).unwrap();
    assert!(biscuit1_deser.verify(root.public));
    let biscuit1_logic = biscuit1_deser.deserialize_logic().unwrap();

    // new caveat: can only have read access1
    let mut block2 = biscuit1_logic.create_block();
    block2.caveats.push(rule(caveat1, &[var("X")], &[
      pred(resource, &[&ambient, &var("X")]),
      pred(operation, &[&ambient, &read]),
      pred(right, &[&authority, &var("X"), &read])
    ]));

    biscuit1_logic.adjust_block_symbols(&mut block2);

    let keypair2 = KeyPair::new(&mut rng);
    let biscuit2 = biscuit1_deser.append(&keypair2, &block2);

    let serialized2 = serde_cbor::to_vec(&biscuit2).unwrap();

    println!("generated biscuit token 2: {} bytes\n{}", serialized2.len(), serialized2.to_hex(16));

    let biscuit2_deser: SerializedBiscuit = serde_cbor::from_slice(&serialized2).unwrap();
    assert!(biscuit2_deser.verify(root.public));
    let biscuit2_logic = biscuit2_deser.deserialize_logic().unwrap();

    // new caveat: can only access file1
    let mut block3 = biscuit2_logic.create_block();
    block3.caveats.push(rule(caveat2, &[&file1], &[
      pred(resource, &[&ambient, &file1])
    ]));

    biscuit2_logic.adjust_block_symbols(&mut block3);

    let keypair3 = KeyPair::new(&mut rng);
    let biscuit3 = biscuit2_deser.append(&keypair3, &block3);

    let serialized3 = serde_cbor::to_vec(&biscuit3).unwrap();

    println!("generated biscuit token 3: {} bytes\n{}", serialized3.len(), serialized3.to_hex(16));


    let final_token: SerializedBiscuit = serde_cbor::from_slice(&serialized3).unwrap();
    assert!(final_token.verify(root.public));

    let final_token_logic = final_token.deserialize_logic().unwrap();

    {
      let ambient_facts = vec![
        fact(resource, &[&ambient, &file1]),
        fact(operation, &[&ambient, &read]),
      ];
      let ambient_rules = vec![];

      final_token_logic.check(ambient_facts, ambient_rules).unwrap();
    }

    {
      let ambient_facts = vec![
        fact(resource, &[&ambient, &file2]),
        fact(operation, &[&ambient, &write]),
      ];
      let ambient_rules = vec![];

      final_token_logic.check(ambient_facts, ambient_rules).unwrap();
    }

    panic!()
    /*
    let ambient_facts = vec![
      fact(resource, &[&ambient, &file1]),
      fact(operation, &[&ambient, &read]),
    ];
    let ambient_rules = vec![];

    bench.iter(|| {
      let w = World::biscuit_create(&mut syms, authority_facts.clone(), authority_rules.clone(),
        ambient_facts.clone(), ambient_rules.clone());

      let res = w.query_rule(rule(caveat1, &[var("X")], &[
        pred(resource, &[&ambient, &var("X")]),
        pred(operation, &[&ambient, &read]),
        pred(right, &[&authority, &var("X"), &read])
      ]));

      assert!(!res.is_empty());

      let res = w.query_rule(rule(caveat2, &[&file1], &[
        pred(resource, &[&ambient, &file1])
      ]));

      assert!(!res.is_empty());
    });
    */
  }
}
