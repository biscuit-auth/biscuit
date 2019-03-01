use datalog::{SymbolTable, ID};
use super::Block;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone,Debug)]
pub struct BlockBuilder {
  pub index: u32,
  pub symbols_start: usize,
  pub symbols: SymbolTable,
  pub facts: Vec<datalog::Fact>,
  pub caveats: Vec<datalog::Rule>,
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

  pub fn add_fact(&mut self, fact: &Fact) {
    let f = fact.convert(&mut self.symbols);
    self.facts.push(f);
  }

  pub fn add_caveat(&mut self, caveat: &Rule) {
    let c = caveat.convert(&mut self.symbols);
    self.caveats.push(c);
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

#[derive(Debug,Clone,PartialEq,Hash,Eq)]
pub enum Atom {
  Symbol(String),
  Variable(u32),
  Integer(i64),
  Str(String),
  Date(u64),
}

impl Atom {
  pub fn convert(&self, symbols: &mut SymbolTable) -> ID {
    match self {
      Atom::Symbol(s) => ID::Symbol(symbols.insert(s)),
      Atom::Variable(i) => ID::Variable(*i),
      Atom::Integer(i) => ID::Integer(*i),
      Atom::Str(s) => ID::Str(s.clone()),
      Atom::Date(d) => ID::Date(*d),
    }
  }
}

impl From<&Atom> for Atom {
  fn from(i: &Atom) -> Self {
    match i {
      Atom::Symbol(ref s) => Atom::Symbol(s.clone()),
      Atom::Variable(ref v) => Atom::Variable(*v),
      Atom::Integer(ref i) => Atom::Integer(*i),
      Atom::Str(ref s) => Atom::Str(s.clone()),
      Atom::Date(ref d) => Atom::Date(*d),
    }
  }
}

impl AsRef<Atom> for Atom {
  fn as_ref(&self) -> &Atom {
    self
  }
}

#[derive(Debug,Clone,PartialEq,Hash,Eq)]
pub struct Predicate {
  pub name: String,
  pub ids: Vec<Atom>,
}

impl Predicate {
  pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Predicate {
    let name = symbols.insert(&self.name);
    let mut ids = vec![];

    for id in self.ids.iter() {
      ids.push(id.convert(symbols));
    }

    datalog::Predicate { name, ids }
  }
}

impl Predicate {
  pub fn new(name: String, ids: &[Atom]) -> Predicate {
    Predicate { name, ids: ids.to_vec() }
  }
}

impl AsRef<Predicate> for Predicate {
  fn as_ref(&self) -> &Predicate {
    self
  }
}

#[derive(Debug,Clone,PartialEq,Hash,Eq)]
pub struct Fact(pub Predicate);

impl Fact {
  pub fn new(name: String, ids: &[Atom]) -> Fact {
    Fact(Predicate::new(name, ids))
  }
}

impl Fact {
  pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Fact {
    datalog::Fact(self.0.convert(symbols))
  }
}


#[derive(Debug,Clone,PartialEq)]
pub struct Rule(pub Predicate, pub Vec<Predicate>, pub Vec<datalog::Constraint>);

impl Rule {
  pub fn convert(&self, symbols: &mut SymbolTable) -> datalog::Rule {
    let head = self.0.convert(symbols);
    let mut body = vec![];
    let mut constraints = vec![];

    for p in self.1.iter() {
      body.push(p.convert(symbols));
    }

    for c in self.2.iter() {
      constraints.push(c.clone());
    }

    datalog::Rule(head, body, constraints)
  }
}

pub fn fact<I:AsRef<Atom>>(name: &str, ids: &[I]) -> Fact {
  Fact(pred(name, ids))
  /*Fact(Predicate {
    name.to_string(),
    ids: ids.iter().map(|id| id.as_ref().clone()).collect(),
  })*/
}

pub fn pred<I: AsRef<Atom>>(name: &str, ids: &[I]) -> Predicate {
  Predicate {
    name: name.to_string(),
    ids: ids.iter().map(|id| id.as_ref().clone()).collect(),
  }
}

pub fn rule<I: AsRef<Atom>, P: AsRef<Predicate>>(head_name: &str, head_ids: &[I], predicates: &[P]) -> Rule {
  Rule(
    pred(head_name, head_ids),
    predicates.iter().map(|p| p.as_ref().clone()).collect(),
    Vec::new()
  )
}

pub fn constrained_rule<I: AsRef<Atom>, P: AsRef<Predicate>, C: AsRef<datalog::Constraint>>(
  head_name: &str, head_ids: &[I], predicates: &[P], constraints: &[C]) -> Rule {
  Rule(
    pred(head_name, head_ids),
    predicates.iter().map(|p| p.as_ref().clone()).collect(),
    constraints.iter().map(|c| c.as_ref().clone()).collect(),
  )
}

pub fn int(i: i64) -> Atom {
  Atom::Integer(i)
}

pub fn string(s: &str) -> Atom {
  Atom::Str(s.to_string())
}

pub fn s(s: &str) -> Atom {
  Atom::Symbol(s.to_string())
}

pub fn date(t: &SystemTime) -> Atom {
  let dur = t.duration_since(UNIX_EPOCH).unwrap();
  Atom::Date(dur.as_secs())
}

pub fn var(i: u32) -> Atom {
  Atom::Variable(i)
}
