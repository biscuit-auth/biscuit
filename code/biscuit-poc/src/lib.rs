extern crate datalog_with_constraints as datalog;
extern crate biscuit_vrf as vrf;
extern crate rand;
extern crate curve25519_dalek;
extern crate serde;
extern crate serde_cbor;
#[macro_use]
extern crate nom;

use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Serialize, Deserialize};
use vrf::KeyPair;
use datalog::*;
use ser::SerializedBiscuit;
use std::collections::HashSet;

mod ser;

pub fn default_symbol_table() -> SymbolTable {
  let mut syms = SymbolTable::new();
  syms.insert("authority");
  syms.insert("ambient");

  syms
}

pub struct Biscuit {
  authority: Block,
  blocks: Vec<Block>,
  symbols: SymbolTable,
  container: SerializedBiscuit,
}

impl Biscuit {
  pub fn new(root: &KeyPair, authority: &Block) -> Biscuit {
    let mut authority = authority.clone();
    let symbols = authority.symbols.clone();

    Biscuit::adjust_authority_symbols(&mut authority);

    let blocks = vec![];

    let container = SerializedBiscuit::new(root, &authority);

    Biscuit { authority, blocks, symbols, container }
  }

  pub fn from(slice: &[u8], root: RistrettoPoint) -> Result<Self, String> {
    let container = SerializedBiscuit::from(slice, root)?;

    let authority: Block = serde_cbor::from_slice(&container.authority).map_err(|e| format!("error deserializing authority block: {:?}", e))?;

    if authority.index != 0 {
      return Err(String::from("authority block should have index 0"));
    }

    let mut blocks = vec![];

    let mut index = 1;
    for block in container.blocks.iter() {
      let deser:Block = serde_cbor::from_slice(&block).map_err(|e| format!("error deserializing block: {:?}", e))?;
      if deser.index != index {
        return Err(format!("invalid index {} for block n°{}", deser.index, index));
      }
      blocks.push(deser);

      index += 1;
    }

    let mut symbols = default_symbol_table();
    symbols.symbols.extend(authority.symbols.symbols.iter().cloned());

    for block in blocks.iter() {
      symbols.symbols.extend(block.symbols.symbols.iter().cloned());
    }

    println!("Biscuit::from: symbols == {:#?}", symbols);

    Ok(Biscuit { authority, blocks, symbols, container })
  }

  pub fn to_vec(&self) -> Vec<u8> {
    self.container.to_vec()
  }

  pub fn check(&self, mut ambient_facts: Vec<Fact>, ambient_rules: Vec<Rule>) -> Result<(), Vec<String>> {
    let mut world = World::new();

    let authority_index = self.symbols.get("authority").unwrap();
    let ambient_index = self.symbols.get("ambient").unwrap();

    for fact in self.authority.facts.iter().cloned() {
      if fact.0.ids[0] != ID::Symbol(authority_index) {
        return Err(vec![format!("invalid authority fact: {}", self.symbols.print_fact(&fact))]);
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
        return Err(vec![format!("invalid ambient fact: {}", self.symbols.print_fact(&fact))]);
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

      match block.check(i, w, &self.symbols) {
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

  pub fn create_block(&self) -> BlockBuilder {
    BlockBuilder::new((1 + self.blocks.len()) as u32, self.symbols.clone())
  }

  pub fn append(&self, keypair: &KeyPair, block: Block) -> Result<Self, String> {
    let h1 = self.symbols.symbols.iter().collect::<HashSet<_>>();
    let h2 = block.symbols.symbols.iter().collect::<HashSet<_>>();
    println!("h1: {:#?}\nh2: {:#?}", h1, h2);

    if !h1.is_disjoint(&h2) {
      return Err(String::from("symbol tables should have no overlap"));
    }

    if block.index as usize != 1 + self.blocks.len() {
      return Err(String::from("invalid block index"));
    }


    let authority = self.authority.clone();
    let mut blocks = self.blocks.clone();
    let mut symbols = self.symbols.clone();
    let container = self.container.append(keypair, &block);
    symbols.symbols.extend(block.symbols.symbols.iter().cloned());
    blocks.push(block);

    Ok(Biscuit { authority, blocks, symbols, container })
  }

  pub fn adjust_authority_symbols(block: &mut Block) {
    let base_symbols = default_symbol_table();

    let new_syms = block.symbols.symbols.split_off(base_symbols.symbols.len());

    block.symbols.symbols = new_syms;
  }

  pub fn adjust_block_symbols(&self, block: &mut Block) {
    let new_syms = block.symbols.symbols.split_off(self.symbols.symbols.len());
    println!("adjusting block symbols from {:#?}\nto {:#?}", block.symbols, new_syms);

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

  pub fn symbol_add(&mut self, s: &str) -> ID {
    self.symbols.add(s)
  }

  pub fn symbol_insert(&mut self, s: &str) -> u64 {
    self.symbols.insert(s)
  }

  pub fn check(&self, i: usize, mut world: World, symbols: &SymbolTable) -> Result<(), Vec<String>> {
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
pub struct BlockBuilder {
  pub index: u32,
  pub symbols_start: usize,
  pub symbols: SymbolTable,
  pub facts: Vec<Fact>,
  pub caveats: Vec<Rule>,
}

impl BlockBuilder {
  pub fn new(index: u32, base_symbols: SymbolTable) -> BlockBuilder {
    BlockBuilder {
      index,
      symbols_start: base_symbols.symbols.len(),
      symbols: base_symbols,
      facts: vec![],
      caveats: vec![],
    }
  }

  pub fn symbol_add(&mut self, s: &str) -> ID {
    self.symbols.add(s)
  }

  pub fn symbol_insert(&mut self, s: &str) -> u64 {
    self.symbols.insert(s)
  }

  pub fn to_block(mut self) -> Block {
    let new_syms = self.symbols.symbols.split_off(self.symbols_start);

    self.symbols.symbols = new_syms;

    Block {
      index: self.index,
      symbols: self.symbols,
      facts: self.facts,
      caveats: self.caveats,
    }
  }
}


#[cfg(test)]
mod tests {
  use super::*;
  use rand::prelude::*;
  use crate::ser::SerializedBiscuit;
  use nom::HexDisplay;
  use vrf::KeyPair;

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
    println!("authority symbols: {:#?}", authority_block.symbols);
    authority_block.facts = vec![
      fact(right, &[&authority, &file1, &read]),
      fact(right, &[&authority, &file2, &read]),
      fact(right, &[&authority, &file1, &write]),
    ];

    Biscuit::adjust_authority_symbols(&mut authority_block);

    let root = KeyPair::new(&mut rng);

    let biscuit1 = Biscuit::new(&root, &authority_block);
    let serialized1 = biscuit1.to_vec();

    println!("generated biscuit token: {} bytes:\n{}", serialized1.len(), serialized1.to_hex(16));

    let biscuit1_deser = Biscuit::from(&serialized1, root.public).unwrap();

    // new caveat: can only have read access1
    let mut block2 = biscuit1_deser.create_block();
    let resource = block2.symbols.insert("resource");
    let operation = block2.symbols.insert("operation");
    let caveat1 = block2.symbols.insert("caveat1");

    block2.caveats.push(rule(caveat1, &[var("X")], &[
      pred(resource, &[&ambient, &var("X")]),
      pred(operation, &[&ambient, &read]),
      pred(right, &[&authority, &var("X"), &read])
    ]));

    let keypair2 = KeyPair::new(&mut rng);
    let biscuit2 = biscuit1_deser.append(&keypair2, block2.to_block()).unwrap();

    let serialized2 = biscuit2.to_vec();

    println!("generated biscuit token 2: {} bytes\n{}", serialized2.len(), serialized2.to_hex(16));

    let biscuit2_deser = Biscuit::from(&serialized2, root.public).unwrap();

    // new caveat: can only access file1
    let mut block3 = biscuit2_deser.create_block();
    let caveat2 = block3.symbols.insert("caveat2");

    block3.caveats.push(rule(caveat2, &[&file1], &[
      pred(resource, &[&ambient, &file1])
    ]));

    let keypair3 = KeyPair::new(&mut rng);
    let biscuit3 = biscuit2_deser.append(&keypair3, block3.to_block()).unwrap();

    let serialized3 = biscuit3.to_vec();

    println!("generated biscuit token 3: {} bytes\n{}", serialized3.len(), serialized3.to_hex(16));


    let final_token = Biscuit::from(&serialized3, root.public).unwrap();

    {
      let ambient_facts = vec![
        fact(resource, &[&ambient, &file1]),
        fact(operation, &[&ambient, &read]),
      ];
      let ambient_rules = vec![];

      let res = final_token.check(ambient_facts, ambient_rules);
      println!("res1: {:?}", res);
      res.unwrap();
    }

    {
      let ambient_facts = vec![
        fact(resource, &[&ambient, &file2]),
        fact(operation, &[&ambient, &write]),
      ];
      let ambient_rules = vec![];

      let res = final_token.check(ambient_facts, ambient_rules);
      println!("res2: {:#?}", res);
      res.unwrap();
    }

    panic!()
  }
}
