#![cfg_attr(feature = "unstable", feature(test))]
#[cfg(all(feature = "unstable", test))]
extern crate test;
extern crate sha2;

use std::fmt;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use std::convert::AsRef;
use std::collections::{HashMap,HashSet};
use sha2::{Sha256, Digest};

mod biscuit;

pub type Symbol = u64;

#[derive(Debug,Clone,PartialEq,Hash,Eq)]
pub enum ID {
  Symbol(Symbol),
  Variable(u32),
  Integer(i64),
  Str(String),
  Date(u64),
}

impl From<&ID> for ID {
  fn from(i: &ID) -> Self {
    match i {
      ID::Symbol(ref s) => ID::Symbol(*s),
      ID::Variable(ref v) => ID::Variable(*v),
      ID::Integer(ref i) => ID::Integer(*i),
      ID::Str(ref s) => ID::Str(s.clone()),
      ID::Date(ref d) => ID::Date(*d),
    }
  }
}

impl AsRef<ID> for ID {
  fn as_ref(&self) -> &ID {
    self
  }
}

#[derive(Debug,Clone,PartialEq,Hash,Eq)]
pub struct Predicate {
  pub name: Symbol,
  pub ids: Vec<ID>,
}

impl Predicate {
  pub fn new(name: Symbol, ids: &[ID]) -> Predicate {
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
  pub fn new(name: Symbol, ids: &[ID]) -> Fact {
    Fact(Predicate::new(name, ids))
  }
}

#[derive(Debug,Clone,PartialEq)]
pub struct Rule(pub Predicate, pub Vec<Predicate>, pub Vec<Constraint>);

#[derive(Debug,Clone,PartialEq)]
pub struct Constraint {
  pub id: u32,
  pub kind: ConstraintKind,
}

impl AsRef<Constraint> for Constraint {
  fn as_ref(&self) -> &Constraint {
    self
  }
}

#[derive(Debug,Clone,PartialEq)]
pub enum ConstraintKind {
  Int(IntConstraint),
  Str(StrConstraint),
  Date(DateConstraint),
  Symbol(SymbolConstraint),
}

#[derive(Debug,Clone,PartialEq)]
pub enum IntConstraint {
  Lower(i64),
  Larger(i64),
  Equal(i64),
  In(HashSet<i64>),
  NotIn(HashSet<i64>),
}

#[derive(Debug,Clone,PartialEq)]
pub enum StrConstraint {
  Prefix(String),
  Suffix(String),
  Equal(String),
  In(HashSet<String>),
  NotIn(HashSet<String>),
}

#[derive(Debug,Clone,PartialEq)]
pub enum DateConstraint {
  Before(u64),
  After(u64),
}

#[derive(Debug,Clone,PartialEq)]
pub enum SymbolConstraint {
  In(HashSet<u64>),
  NotIn(HashSet<u64>),
}

impl Constraint {
  pub fn check(&self, name: u32, id: &ID) -> bool {
    if name != self.id {
      return true;
    }

    match (id, &self.kind) {
      (ID::Variable(_), _) => panic!("should not check constraint on a variable"),
      (ID::Integer(i), ConstraintKind::Int(c)) => match c {
        IntConstraint::Lower(j)  => *i < *j,
        IntConstraint::Larger(j) => *i > *j,
        IntConstraint::Equal(j)  => *i == *j,
        IntConstraint::In(h)     => h.contains(i),
        IntConstraint::NotIn(h)  => !h.contains(i),
      },
      (ID::Str(s), ConstraintKind::Str(c)) => match c {
        StrConstraint::Prefix(pref) => s.as_str().starts_with(pref.as_str()),
        StrConstraint::Suffix(suff) => s.as_str().ends_with(suff.as_str()),
        StrConstraint::Equal(s2)    => &s == &s2,
        StrConstraint::In(h)        => h.contains(s),
        StrConstraint::NotIn(h)     => !h.contains(s),
      },
      (ID::Date(d), ConstraintKind::Date(c)) => match c {
        DateConstraint::Before(b) => d <=b,
        DateConstraint::After(b) => d >= b,
      },
      (ID::Symbol(s), ConstraintKind::Symbol(c)) => match c {
        SymbolConstraint::In(h)    => h.contains(s),
        SymbolConstraint::NotIn(h) => !h.contains(s),
      },
      _ => false,
    }
  }
}

impl fmt::Display for Fact {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}({:?})", self.0.name, self.0.ids)
  }
}

impl Rule {
  pub fn apply(&self, facts: &HashSet<Fact>, new_facts: &mut Vec<Fact>) {
    let variables_set = self.1.iter().flat_map(|pred| pred.ids.iter().filter(|id| {
      match id {
        ID::Variable(_) => true,
        _ => false
      }
    }).map(|id| {
      match id {
        ID::Variable(i) => *i,
        _ => unreachable!(),
      }
    })).collect::<HashSet<_>>();

    let variables = MatchedVariables::new(variables_set);

    new_facts.extend(CombineIt::new(variables, &self.1, &self.2, facts).map(|h| {
      let mut p = self.0.clone();
      for index in 0..p.ids.len() {
        let value = match &p.ids[index] {
          //FIXME
          ID::Variable(i) => h.get(i).unwrap(),
          _ => continue,
        };

        p.ids[index] = value.clone();
      }

      Fact(p)
    }));
  }
}

/// recursive iterator for rule application
pub struct CombineIt<'a> {
  variables: MatchedVariables,
  predicates: &'a [Predicate],
  constraints: &'a [Constraint],
  all_facts: &'a HashSet<Fact>,
  current_facts: Box<Iterator<Item=&'a Fact> + 'a>,
  current_it: Option<Box<CombineIt<'a>>>,
}

impl<'a> CombineIt<'a> {
  pub fn new(variables: MatchedVariables, predicates: &'a [Predicate], constraints: &'a [Constraint], facts: &'a HashSet<Fact>) -> Self {
    let p = predicates[0].clone();
    CombineIt {
      variables,
      predicates,
      constraints,
      all_facts: facts,
      current_facts: Box::new(facts.iter().filter(move |fact| match_preds(&fact.0, &p))),
      current_it: None,
    }
  }
}

impl<'a> Iterator for CombineIt<'a> {
  type Item = HashMap<u32, ID>;

  fn next(&mut self) -> Option<HashMap<u32, ID>> {
    // if we're the last iterator in the recursive chain, stop here
    if self.predicates.is_empty() {
      return self.variables.complete();
    }

    loop {

      if self.current_it.is_none() {
        //fix the first predicate
        let pred = &self.predicates[0];

        loop {
          if let Some(current_fact) = self.current_facts.next() {
            // create a new MatchedVariables in which we fix variables we could unify
            // from our first predicate and the current fact
            let mut vars = self.variables.clone();
            let mut match_ids = true;
            for (key, id) in pred.ids.iter().zip(&current_fact.0.ids) {
              if let (ID::Variable(k), id) = (key, id) {
                for c in self.constraints {
                  if !c.check(*k, id) {
                    match_ids = false;
                    break;
                  }
                }
                if !vars.insert(*k, &id) {
                  match_ids = false;
                }

                if !match_ids {
                  break;
                }
              }
            }

            if !match_ids {
              continue;
            }

            if self.predicates.len() == 1 {
              if let Some(val) = vars.complete() {
                return Some(val);
              } else {
                continue;
              }
            } else {
              // create a new iterator with the matched variables, the rest of the predicates,
              // and all of the facts
              self.current_it = Some(Box::new(CombineIt::new(vars, &self.predicates[1..], self.constraints,
                &self.all_facts)));
            }
            break;
          } else {
            return None;
          }
        }
      }

      if self.current_it.is_none() {
        break None;
      }

      if let Some(val) = self.current_it.as_mut().and_then(|it| it.next()) {
        break Some(val);
      } else {
        self.current_it = None;
      }
    }
  }
}

#[derive(Debug,Clone,PartialEq)]
pub struct MatchedVariables(pub HashMap<u32, Option<ID>>);

impl MatchedVariables {
  pub fn new(import: HashSet<u32>) -> Self {
    MatchedVariables(import.iter().map(|key| (key.clone(), None)).collect())
  }

  pub fn insert(&mut self, key: u32, value: &ID) -> bool {
    match self.0.get(&key) {
      Some(None) => {
        self.0.insert(key, Some(value.clone()));
        true
      },
      Some(Some(v)) => value == v,
      None => false
    }
  }

  pub fn is_complete(&self) -> bool {
    self.0.values().all(|v| v.is_some())
  }

  pub fn complete(&self) -> Option<HashMap<u32, ID>> {
    if self.is_complete() {
      Some(self.0.iter().map(|(k, v)| (k.clone(), v.clone().unwrap())).collect())
    } else {
      None
    }
  }
}

pub fn fact<I:AsRef<ID>>(name: Symbol, ids: &[I]) -> Fact {
  Fact(Predicate {
    name,
    ids: ids.iter().map(|id| id.as_ref().clone()).collect(),
  })
}

pub fn pred<I: AsRef<ID>>(name: Symbol, ids: &[I]) -> Predicate {
  Predicate {
    name,
    ids: ids.iter().map(|id| id.as_ref().clone()).collect(),
  }
}

pub fn rule<I: AsRef<ID>, P: AsRef<Predicate>>(head_name: Symbol, head_ids: &[I], predicates: &[P]) -> Rule {
  Rule(
    pred(head_name, head_ids),
    predicates.iter().map(|p| p.as_ref().clone()).collect(),
    Vec::new()
  )
}

pub fn constrained_rule<I: AsRef<ID>, P: AsRef<Predicate>, C: AsRef<Constraint>>(
  head_name: Symbol, head_ids: &[I], predicates: &[P], constraints: &[C]) -> Rule {
  Rule(
    pred(head_name, head_ids),
    predicates.iter().map(|p| p.as_ref().clone()).collect(),
    constraints.iter().map(|c| c.as_ref().clone()).collect(),
  )
}

pub fn int(i: i64) -> ID {
  ID::Integer(i)
}

pub fn string(s: &str) -> ID {
  ID::Str(s.to_string())
}

pub fn date(t: &SystemTime) -> ID {
  let dur = t.duration_since(UNIX_EPOCH).unwrap();
  ID::Date(dur.as_secs())
}

/// warning: collision risk
pub fn var(name: &str) -> ID {
  let mut hasher = Sha256::new();
  hasher.input(name);
  let res = hasher.result();
  let id: u32 = res[0] as u32 + ((res[1] as u32) << 8) + ((res[2] as u32) << 16) + ((res[3] as u32) << 24);
  ID::Variable(id)
}

pub fn match_preds(pred1: &Predicate, pred2: &Predicate) -> bool {
  pred1.name == pred2.name &&
    pred1.ids.len() == pred2.ids.len() &&
    pred1.ids.iter().zip(&pred2.ids).all(|(fid, pid)| {
      match (fid, pid) {
        (_, ID::Variable(_)) => true,
        (ID::Variable(_), _) => true,
        (ID::Symbol(i), ID::Symbol(ref j)) => i == j,
        (ID::Integer(i), ID::Integer(j)) => i == j,
        (ID::Str(i), ID::Str(j)) => i == j,
        _ => false
      }
    })

}

#[derive(Debug,Clone,PartialEq)]
pub struct World {
  pub facts: HashSet<Fact>,
  pub rules: Vec<Rule>,
}

impl World {
  pub fn new() -> Self {
    World {
      facts: HashSet::new(),
      rules: Vec::new(),
    }
  }

  pub fn add_fact(&mut self, fact: Fact) {
    self.facts.insert(fact);
  }

  pub fn add_rule(&mut self, rule: Rule) {
    self.rules.push(rule);
  }

  pub fn run(&mut self) {
    let mut index = 0;
    loop {
      let mut new_facts:Vec<Fact> = Vec::new();
      for rule in self.rules.iter() {
        rule.apply(&self.facts, &mut new_facts);
        //println!("new_facts after applying {:?}:\n{:#?}", rule, new_facts);
      }

      let len = self.facts.len();
      self.facts.extend(new_facts.drain(..));
      if self.facts.len() == len {
        break;
      }

      index+= 1;
      if index == 100 {
        panic!();
      }
    }

  }

  pub fn query(&self, pred: Predicate) -> Vec<&Fact> {
    let facts = self.facts.iter().filter(|f| {
      &f.0.name == &pred.name &&
          f.0.ids.iter().zip(&pred.ids).all(|(fid, pid)| {
            match (fid, pid) {
              (ID::Symbol(_), ID::Variable(_)) => true,
              (ID::Symbol(i), ID::Symbol(ref j)) => i == j,
              (ID::Integer(i), ID::Integer(ref j)) => i == j,
              (ID::Str(i), ID::Str(ref j)) => i == j,
              _ => false
            }
          })
      }).collect::<Vec<_>>();

    facts
  }

  pub fn query_rule(&self, rule: Rule) -> Vec<Fact> {
    let mut new_facts:Vec<Fact> = Vec::new();
    rule.apply(&self.facts, &mut new_facts);
    new_facts
  }
}

#[derive(Clone,Debug,PartialEq)]
pub struct SymbolTable {
  symbols: Vec<String>,
}

impl SymbolTable {
  pub fn new() -> Self {
    SymbolTable { symbols: Vec::new() }
  }

  pub fn insert(&mut self, s: &str) -> Symbol {
    match self.symbols.iter().position(|sym| sym.as_str() == s) {
      Some(index) => index as u64,
      None => {
        self.symbols.push(s.to_string());
        (self.symbols.len() - 1) as u64
      }
    }
  }

  pub fn add(&mut self, s: &str) -> ID {
    let id = self.insert(s);
    ID::Symbol(id)
  }

  pub fn print_fact(&self, f: &Fact) -> String {
    format!("{}", self.print_predicate(&f.0))
  }

  pub fn print_predicate(&self, p: &Predicate) -> String {
    let strings = p.ids.iter().map(|id| {
        match id {
          ID::Variable(i) => format!("{}?", i),
          ID::Integer(i) => i.to_string(),
          ID::Str(s) => s.clone(),
          ID::Symbol(index) => format!("#{}", self.symbols[*index as usize]),
          ID::Date(d) => {
            let t = UNIX_EPOCH + Duration::from_secs(*d);
            format!("{:?}", t)
          }
        }
      }).collect::<Vec<_>>();
    format!("{}({})", self.symbols[p.name as usize], strings.join(", "))
  }

  pub fn print_constraint(&self, c: &Constraint) -> String {
    match &c.kind {
      ConstraintKind::Int(IntConstraint::Lower(i)) => format!("{}? < {}", c.id, i),
      ConstraintKind::Int(IntConstraint::Larger(i)) => format!("{}? > {}", c.id, i),
      ConstraintKind::Int(IntConstraint::Equal(i)) => format!("{}? == {}", c.id, i),
      ConstraintKind::Int(IntConstraint::In(i)) => format!("{}? in {:?}", c.id, i),
      ConstraintKind::Int(IntConstraint::NotIn(i)) => format!("{}? not in {:?}", c.id, i),
      ConstraintKind::Str(StrConstraint::Prefix(i)) => format!("{}? matches {}*", c.id, i),
      ConstraintKind::Str(StrConstraint::Suffix(i)) => format!("{}? matches *{}", c.id, i),
      ConstraintKind::Str(StrConstraint::Equal(i)) => format!("{}? == {}", c.id, i),
      ConstraintKind::Str(StrConstraint::In(i)) => format!("{}? in {:?}", c.id, i),
      ConstraintKind::Str(StrConstraint::NotIn(i)) => format!("{}? not in {:?}", c.id, i),
      ConstraintKind::Date(DateConstraint::Before(i)) => format!("{}? <= {:?}", c.id, i),
      ConstraintKind::Date(DateConstraint::After(i)) => format!("{}? >= {:?}", c.id, i),
      ConstraintKind::Symbol(SymbolConstraint::In(i)) => format!("{}? in {:?}", c.id, i),
      ConstraintKind::Symbol(SymbolConstraint::NotIn(i)) => format!("{}? not in {:?}", c.id, i),
    }
  }

  pub fn print_rule(&self, r: &Rule) -> String {
    let res = self.print_predicate(&r.0);
    let preds:Vec<_> = r.1.iter().map(|p| self.print_predicate(p)).collect();
    let constraints: Vec<_> = r.2.iter().map(|c| self.print_constraint(c)).collect();

    format!("{} <- {} | {}", res, preds.join(" && "), constraints.join(" && "))
  }
}

pub fn sym(syms: &mut SymbolTable, name: &str) -> ID {
  let id = syms.insert(name);
  ID::Symbol(id)
}


#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn family() {
    let mut w = World::new();
    let mut syms = SymbolTable::new();

    let a = syms.add("A");
    let b = syms.add("B");
    let c = syms.add("C");
    let d = syms.add("D");
    let e = syms.add("e");
    let parent = syms.insert("parent");
    let grandparent = syms.insert("grandparent");

    w.add_fact(fact(parent, &[&a, &b]));
    w.add_fact(fact(parent, &[&b, &c]));
    w.add_fact(fact(parent, &[&c, &d]));

    let r1 = rule(grandparent, &[var("grandparent"), var("grandchild")], &[
      pred(parent, &[var("grandparent"), var("parent")]),
      pred(parent, &[var("parent"), var("grandchild")])
    ]);

    println!("testing r1: {}", syms.print_rule(&r1));
    let query_rule_result = w.query_rule(r1);
    println!("grandparents query_rules: {:?}", query_rule_result);
    println!("current facts: {:?}", w.facts);

    let r2 = rule(grandparent, &[var("grandparent"), var("grandchild")], &[
      pred(parent, &[var("grandparent"), var("parent")]),
      pred(parent, &[var("parent"), var("grandchild")])
    ]);

    println!("adding r2: {}", syms.print_rule(&r2));
    w.add_rule(r2);

    w.run();

    println!("parents:");
    let res = w.query(pred(parent, &[var("parent"), var("child")]));
    for fact in res {
      println!("\t{}", syms.print_fact(fact));
    }

    println!("parents of B: {:?}", w.query(pred(parent, &[&var("parent"), &b])));
    println!("grandparents: {:?}", w.query(pred(grandparent, &[var("grandparent"), var("grandchild")])));
    w.add_fact(fact(parent, &[&c, &e]));
    w.run();
    let mut res = w.query(pred(grandparent, &[var("grandparent"), var("grandchild")]));
    println!("grandparents after inserting parent(C, E): {:?}", res);

    let res = res.drain(..).cloned().collect::<HashSet<_>>();
    let compared = (vec![
      fact(grandparent, &[&a, &c]),
      fact(grandparent, &[&b, &d]),
      fact(grandparent, &[&b, &e])
    ]).drain(..).collect::<HashSet<_>>();
    assert_eq!(res, compared);

    /*w.add_rule(rule("siblings", &[var("A"), var("B")], &[
      pred(parent, &[var(parent), var("A")]),
      pred(parent, &[var(parent), var("B")])
    ]));

    w.run();
    println!("siblings: {:#?}", w.query(pred("siblings", &[var("A"), var("B")])));
    */
  }

  #[test]
  fn numbers() {
    let mut w = World::new();
    let mut syms = SymbolTable::new();

    let abc = syms.add("abc");
    let def = syms.add("def");
    let ghi = syms.add("ghi");
    let jkl = syms.add("jkl");
    let mno = syms.add("mno");
    let aaa = syms.add("AAA");
    let bbb = syms.add("BBB");
    let ccc = syms.add("CCC");
    let t1  = syms.insert("t1");
    let t2  = syms.insert("t2");
    let join = syms.insert("join");

    w.add_fact(fact(t1, &[&int(0), &abc]));
    w.add_fact(fact(t1, &[&int(1), &def]));
    w.add_fact(fact(t1, &[&int(2), &ghi]));
    w.add_fact(fact(t1, &[&int(3), &jkl]));
    w.add_fact(fact(t1, &[&int(4), &mno]));

    w.add_fact(fact(t2, &[&int(0), &aaa, &int(0)]));
    w.add_fact(fact(t2, &[&int(1), &bbb, &int(0)]));
    w.add_fact(fact(t2, &[&int(2), &ccc, &int(1)]));

    let res = w.query_rule(rule(join, &[var("left"), var("right")], &[
      pred(t1, &[var("id"), var("left")]),
      pred(t2, &[var("t2_id"), var("right"), var("id")])
    ]));
    for fact in &res {
      println!("\t{}", syms.print_fact(fact));
    }

    let res2 = res.iter().cloned().collect::<HashSet<_>>();
    let compared = (vec![
      fact(join, &[&abc, &aaa]),
      fact(join, &[&abc, &bbb]),
      fact(join, &[&def, &ccc])
    ]).drain(..).collect::<HashSet<_>>();
    assert_eq!(res2, compared);

    // test constraints
    let res = w.query_rule(constrained_rule(join,
      &[var("left"), var("right")],
      &[
        pred(t1, &[ID::Variable(1234), var("left")]),
        pred(t2, &[var("t2_id"), var("right"), ID::Variable(1234)])
      ],
      &[Constraint {
        id: 1234,
        kind: ConstraintKind::Int(IntConstraint::Lower(1))
      }]
    ));
    for fact in &res {
      println!("\t{}", syms.print_fact(fact));
    }

    let res2 = res.iter().cloned().collect::<HashSet<_>>();
    let compared = (vec![
      fact(join, &[&abc, &aaa]),
      fact(join, &[&abc, &bbb])
    ]).drain(..).collect::<HashSet<_>>();
    assert_eq!(res2, compared);
  }

  #[test]
  fn str() {
    let mut w = World::new();
    let mut syms = SymbolTable::new();

    let app_0 = syms.add("app_0");
    let app_1 = syms.add("app_1");
    let app_2 = syms.add("app_2");
    let route = syms.insert("route");
    let suff  = syms.insert("route suffix");

    w.add_fact(fact(route, &[&int(0), &app_0, &string("example.com")]));
    w.add_fact(fact(route, &[&int(1), &app_1, &string("test.com")]));
    w.add_fact(fact(route, &[&int(2), &app_2, &string("test.fr")]));
    w.add_fact(fact(route, &[&int(3), &app_0, &string("www.example.com")]));
    w.add_fact(fact(route, &[&int(4), &app_1, &string("mx.example.com")]));


    fn test_suffix(w: &World, suff: Symbol, route: Symbol, suffix: &str) -> Vec<Fact> {
      w.query_rule(constrained_rule(suff,
        &[var("app_id"), ID::Variable(1234)],
        &[pred(route, &[ID::Variable(0), var("app_id"), ID::Variable(1234)])],
        &[Constraint {
          id: 1234,
          kind: ConstraintKind::Str(StrConstraint::Suffix(suffix.to_string()))
        }]
      ))
    }

    let res = test_suffix(&w, suff, route, ".fr");
    for fact in &res {
      println!("\t{}", syms.print_fact(fact));
    }

    let res2 = res.iter().cloned().collect::<HashSet<_>>();
    let compared = (vec![
      fact(suff, &[&app_2, &string("test.fr")])
    ]).drain(..).collect::<HashSet<_>>();
    assert_eq!(res2, compared);

    let res = test_suffix(&w, suff, route, "example.com");
    for fact in &res {
      println!("\t{}", syms.print_fact(fact));
    }

    let res2 = res.iter().cloned().collect::<HashSet<_>>();
    let compared = (vec![
      fact(suff, &[&app_0, &string("example.com")]),
      fact(suff, &[&app_0, &string("www.example.com")]),
      fact(suff, &[&app_1, &string("mx.example.com")])
    ]).drain(..).collect::<HashSet<_>>();
    assert_eq!(res2, compared);
  }

  #[test]
  fn date_constraint() {
    let mut w = World::new();
    let mut syms = SymbolTable::new();

    let t1 = SystemTime::now();
    println!("t1 = {:?}", t1);
    let t2 = t1 + Duration::from_secs(10);
    println!("t2 = {:?}", t2);
    let t3 = t2 + Duration::from_secs(30);
    println!("t3 = {:?}", t3);

    let t2_timestamp = t2.duration_since(UNIX_EPOCH).unwrap().as_secs();

    let abc = syms.add("abc");
    let def = syms.add("def");
    let x   = syms.insert("x");
    let before = syms.insert("before");
    let after = syms.insert("after");

    w.add_fact(fact(x, &[&date(&t1), &abc]));
    w.add_fact(fact(x, &[&date(&t3), &def]));

    let r1 = constrained_rule(before,
      &[ID::Variable(1234), var("val")],
      &[
        pred(x, &[ID::Variable(1234), var("val")]),
      ],
      &[
        Constraint {
          id: 1234,
          kind: ConstraintKind::Date(DateConstraint::Before(t2_timestamp))
        },
        Constraint {
          id: 1234,
          kind: ConstraintKind::Date(DateConstraint::After(0))
        }
      ]
    );

    println!("testing r1: {}", syms.print_rule(&r1));
    let res = w.query_rule(r1);
    for fact in &res {
      println!("\t{}", syms.print_fact(fact));
    }

    let res2 = res.iter().cloned().collect::<HashSet<_>>();
    let compared = (vec![
      fact(before, &[&date(&t1), &abc]),
    ]).drain(..).collect::<HashSet<_>>();
    assert_eq!(res2, compared);

    let r2 = constrained_rule(after,
      &[ID::Variable(1234), var("val")],
      &[
        pred(x, &[ID::Variable(1234), var("val")]),
      ],
      &[
        Constraint {
          id: 1234,
          kind: ConstraintKind::Date(DateConstraint::After(t2_timestamp))
        },
        Constraint {
          id: 1234,
          kind: ConstraintKind::Date(DateConstraint::After(0))
        }
      ]
    );

    println!("testing r2: {}", syms.print_rule(&r2));
    let res = w.query_rule(r2);
    for fact in &res {
      println!("\t{}", syms.print_fact(fact));
    }

    let res2 = res.iter().cloned().collect::<HashSet<_>>();
    let compared = (vec![
      fact(after, &[&date(&t3), &def]),
    ]).drain(..).collect::<HashSet<_>>();
    assert_eq!(res2, compared);
  }

  #[test]
  fn set_constraint() {
    let mut w = World::new();
    let mut syms = SymbolTable::new();

    let abc = syms.add("abc");
    let def = syms.add("def");
    let x   = syms.insert("x");
    let int_set = syms.insert("int_set");
    let symbol_set = syms.insert("symbol_set");
    let string_set = syms.insert("string_set");

    w.add_fact(fact(x, &[&abc, &int(0), &string("test")]));
    w.add_fact(fact(x, &[&def, &int(2), &string("hello")]));

    let res = w.query_rule(constrained_rule(int_set,
      &[var("sym"), var("str")],
      &[
        pred(x, &[var("sym"), ID::Variable(0), var("str")]),
      ],
      &[
        Constraint {
          id: 0,
          kind: ConstraintKind::Int(IntConstraint::In([0, 1].iter().cloned().collect()))
        }
      ]
    ));
    for fact in &res {
      println!("\t{}", syms.print_fact(fact));
    }

    let res2 = res.iter().cloned().collect::<HashSet<_>>();
    let compared = (vec![
      fact(int_set, &[&abc, &string("test")]),
    ]).drain(..).collect::<HashSet<_>>();
    assert_eq!(res2, compared);

    let abc_sym_id = syms.insert("abc");
    let ghi_sym_id = syms.insert("ghi");

    let res = w.query_rule(constrained_rule(symbol_set,
      &[ID::Variable(0), var("int"), var("str")],
      &[
        pred(x, &[ID::Variable(0), var("int"), var("str")]),
      ],
      &[
        Constraint {
          id: 0,
          kind: ConstraintKind::Symbol(SymbolConstraint::NotIn([abc_sym_id, ghi_sym_id].iter().cloned().collect()))
        }
      ]
    ));
    for fact in &res {
      println!("\t{}", syms.print_fact(fact));
    }

    let res2 = res.iter().cloned().collect::<HashSet<_>>();
    let compared = (vec![
      fact(symbol_set, &[&def, &int(2), &string("hello")]),
    ]).drain(..).collect::<HashSet<_>>();
    assert_eq!(res2, compared);

    let res = w.query_rule(constrained_rule(string_set,
      &[var("sym"), var("int"), ID::Variable(0)],
      &[
        pred(x, &[var("sym"), var("int"), ID::Variable(0)]),
      ],
      &[
        Constraint {
          id: 0,
          kind: ConstraintKind::Str(StrConstraint::In(["test".to_string(), "aaa".to_string()].iter().cloned().collect()))
        }
      ]
    ));
    for fact in &res {
      println!("\t{}", syms.print_fact(fact));
    }

    let res2 = res.iter().cloned().collect::<HashSet<_>>();
    let compared = (vec![
      fact(string_set, &[&abc, &int(0), &string("test")]),
    ]).drain(..).collect::<HashSet<_>>();
    assert_eq!(res2, compared);
  }
}

#[cfg(test)]
mod bench {
  use super::*;
  use test::Bencher;

  #[bench]
  fn grandparents(bench: &mut Bencher) {
    let mut w = World::new();
    let mut syms = SymbolTable::new();
    let a = syms.add("A");
    let b = syms.add("B");
    let c = syms.add("C");
    let d = syms.add("D");
    let e = syms.add("E");
    let x = syms.add("X");
    let y = syms.add("Y");
    let s0 = syms.add("0");
    let s1 = syms.add("1");
    let s2 = syms.add("2");
    let s3 = syms.add("3");
    let s4 = syms.add("5");
    let aa = syms.add("AA");
    let ab = syms.add("AB");
    let ac = syms.add("AC");
    let ad = syms.add("AD");
    let ae = syms.add("AE");
    let ax = syms.add("AX");
    let ay = syms.add("AY");
    let parent = syms.insert("parent");
    let grandparent = syms.insert("grandparent");

    w.add_fact(fact(parent, &[&a, &b]));
    w.add_fact(fact(parent, &[&b, &c]));
    w.add_fact(fact(parent, &[&c, &d]));
    w.add_fact(fact(parent, &[&c, &e]));
    w.add_fact(fact(parent, &[&x, &c]));
    w.add_fact(fact(parent, &[&y, &b]));
    w.add_fact(fact(parent, &[&a, &s0]));
    w.add_fact(fact(parent, &[&a, &s1]));
    w.add_fact(fact(parent, &[&a, &s2]));
    w.add_fact(fact(parent, &[&a, &s3]));
    w.add_fact(fact(parent, &[&a, &s4]));

    w.add_fact(fact(parent, &[&aa, &ab]));
    w.add_fact(fact(parent, &[&ab, &ac]));
    w.add_fact(fact(parent, &[&ac, &ad]));
    w.add_fact(fact(parent, &[&ac, &ae]));
    w.add_fact(fact(parent, &[&ax, &ac]));
    w.add_fact(fact(parent, &[&ay, &ab]));
    w.add_fact(fact(parent, &[&aa, &s0]));
    w.add_fact(fact(parent, &[&aa, &s1]));
    w.add_fact(fact(parent, &[&aa, &s2]));
    w.add_fact(fact(parent, &[&aa, &s3]));
    w.add_fact(fact(parent, &[&aa, &s4]));

    bench.iter(|| {
      w.query_rule(rule(grandparent, &[var("grandparent"), var("grandchild")], &[
        pred(parent, &[var("grandparent"), var("parent")]),
        pred(parent, &[var("parent"), var("grandchild")])
      ]))
    });
  }

  #[bench]
  fn ancestor(bench: &mut Bencher) {
    let mut w = World::new();
    let mut syms = SymbolTable::new();
    let a = syms.add("A");
    let b = syms.add("B");
    let c = syms.add("C");
    let d = syms.add("D");
    let e = syms.add("E");
    let x = syms.add("X");
    let y = syms.add("Y");
    let parent = syms.insert("parent");
    let ancestor = syms.insert("ancestor");

    w.add_fact(fact(parent, &[&a, &b]));
    w.add_fact(fact(parent, &[&b, &c]));
    w.add_fact(fact(parent, &[&c, &d]));
    w.add_fact(fact(parent, &[&c, &e]));
    w.add_fact(fact(parent, &[&x, &c]));
    w.add_fact(fact(parent, &[&y, &b]));
    w.add_rule(rule(ancestor, &[var("older"), var("younger")], &[
      pred(parent, &[var("older"), var("younger")])
    ]));
    w.add_rule(rule(ancestor, &[var("older"), var("younger")], &[
      pred(parent, &[var("older"), var("middle")]),
      pred(ancestor, &[var("middle"), var("younger")])
    ]));

    bench.iter(|| {
      w.run();
    });
  }
}
