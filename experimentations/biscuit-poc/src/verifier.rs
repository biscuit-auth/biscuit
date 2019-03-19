use super::builder::{Fact,Rule, fact, rule, pred, date, string, s,
  constrained_rule, Atom};
use datalog::{Constraint, ConstraintKind, IntConstraint};
use super::Biscuit;
use std::time::{UNIX_EPOCH, SystemTime};

pub struct Verifier {
  facts: Vec<Fact>,
  rules: Vec<Rule>,
  caveats: Vec<Rule>,
}

impl Verifier {
  pub fn new() -> Self {
    Verifier {
      facts: vec![],
      rules: vec![],
      caveats: vec![]
    }
  }

  pub fn add_fact(&mut self, fact: Fact) {
    self.facts.push(fact);
  }

  pub fn add_rule(&mut self, rule: Rule) {
    self.rules.push(rule);
  }

  pub fn add_caveat(&mut self, caveat: Rule) {
    self.caveats.push(caveat);
  }

  pub fn resource(&mut self, resource: &str) {
    self.facts.push(fact("resource", &[s("ambient"), string(resource)]));
  }

  pub fn operation(&mut self, operation: &str) {
    self.facts.push(fact("operation", &[s("ambient"), s(operation)]));
  }

  pub fn time(&mut self) {
    self.facts.push(fact("time", &[s("ambient"), date(&SystemTime::now())]));
  }

  pub fn revocation_check(&mut self, ids: &[i64]) {
    let caveat = constrained_rule("revocation_check", &[Atom::Variable(0)],
      &[pred("revocation_id", &[Atom::Variable(0)])],
      &[Constraint {
        id: 0,
        kind: ConstraintKind::Int(IntConstraint::NotIn(ids.iter().cloned().collect()))
      }]
    );
    self.add_caveat(caveat);
  }

  pub fn verify(&self, mut token: Biscuit) -> Result<(), Vec<String>> {
    let symbols = &mut token.symbols;

    let mut ambient_facts = vec![];
    let mut ambient_rules = vec![];
    let mut ambient_caveats = vec![];

    for fact in self.facts.iter() {
      ambient_facts.push(fact.convert(symbols));
    }

    for rule in self.rules.iter() {
      ambient_rules.push(rule.convert(symbols));
    }

    for caveat in self.caveats.iter() {
      ambient_caveats.push(caveat.convert(symbols));
    }

    token.check(ambient_facts, ambient_rules, ambient_caveats)
  }
}
