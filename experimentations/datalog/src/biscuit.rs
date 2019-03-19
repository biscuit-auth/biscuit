use super::*;

impl World {
  pub fn biscuit_create(table: &mut SymbolTable,
    mut authority_facts: Vec<Fact>, mut authority_rules: Vec<Rule>,
    mut ambient_facts: Vec<Fact>, ambient_rules: Vec<Rule>) -> World {
    let mut w = World::new();
    let authority_index = table.insert("authority");
    let ambient_index = table.insert("ambient");

    for fact in authority_facts.drain(..) {
      if fact.0.ids[0] != ID::Symbol(authority_index) {
        panic!("invalid authority facts");
      }

      w.facts.insert(fact);
    }

    for rule in authority_rules.drain(..) {
      w.rules.push(rule);
    }

    w.run();

    if w.facts.iter().find(|fact| fact.0.ids[0] != ID::Symbol(authority_index)).is_some() {
      panic!("generated authority facts should have the authority context");
    }

    //remove authority rules: we cannot create facts anymore in authority scope
    //w.rules.clear();

    for fact in ambient_facts.drain(..) {
      if fact.0.ids[0] != ID::Symbol(ambient_index) {
        panic!("invalid ambient facts");
      }

      w.facts.insert(fact);
    }

    for rule in ambient_rules.iter().cloned() {
      w.rules.push(rule);
    }

    w.run();

    // we only keep the verifier rules
    w.rules = ambient_rules;

    w
  }

  pub fn biscuit_add_fact(&mut self, authority_index: u64, ambient_index: u64, fact: Fact) {
    if fact.0.ids[0] == ID::Symbol(authority_index)
      || fact.0.ids[0] == ID::Symbol(ambient_index) {
      panic!("block facts cannot add to authority or ambient contexts");
    }

    self.facts.insert(fact);
  }

  pub fn biscuit_add_rule(&mut self, rule: Rule) {
    self.rules.push(rule);
  }

  pub fn biscuit_run(&mut self, authority_index: u64, ambient_index: u64) {
    let mut index = 0;
    loop {
      let mut new_facts:Vec<Fact> = Vec::new();
      for rule in self.rules.iter() {
        rule.apply(&self.facts, &mut new_facts);
      }

      let len = self.facts.len();

      for fact in new_facts.iter() {
        if fact.0.ids[0] == ID::Symbol(authority_index)
          || fact.0.ids[0] == ID::Symbol(ambient_index) {
          panic!("block rules should not generate authority or ambient facts");
        }
      }

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
}

#[cfg(test)]
mod tests {
  use super::*;
  use super::super::*;

  // example queries from https://github.com/CleverCloud/biscuit/issues/11

  /// example 1 from https://github.com/CleverCloud/biscuit/issues/11#issue-406906214
  #[test]
  fn example1_basic() {
    let mut syms = SymbolTable::new();
    let authority = syms.add("authority");
    let ambient = syms.add("ambient");
    let file1 = syms.add("file1");
    let file2 = syms.add("file2");
    let read = syms.add("read");
    let write = syms.add("write");
    let right = syms.insert("right");
    let resource = syms.insert("resource");
    let operation = syms.insert("operation");
    let caveat1 = syms.insert("caveat1");
    let caveat2 = syms.insert("caveat2");

    let authority_facts = vec![
      fact(right, &[&authority, &file1, &read]),
      fact(right, &[&authority, &file2, &read]),
      fact(right, &[&authority, &file1, &write]),
    ];
    let authority_rules = vec![];
    let ambient_facts = vec![
      fact(resource, &[&ambient, &file1]),
      fact(operation, &[&ambient, &read]),
    ];
    let ambient_rules = vec![];

    for fact in authority_facts.iter() {
      println!("{}", syms.print_fact(&fact));
    }
    for rule in authority_rules.iter() {
      println!("{}", syms.print_rule(&rule));
    }
    for fact in ambient_facts.iter() {
      println!("{}", syms.print_fact(&fact));
    }
    for rule in ambient_rules.iter() {
      println!("{}", syms.print_rule(&rule));
    }

    let w = World::biscuit_create(&mut syms, authority_facts, authority_rules,
    ambient_facts, ambient_rules);

    let r1 = rule(caveat1, &[var("X")], &[
                                pred(resource, &[&ambient, &var("X")]),
                                pred(operation, &[&ambient, &read]),
                                pred(right, &[&authority, &var("X"), &read])
    ]);

    println!("caveat 1: {}", syms.print_rule(&r1));
    let res = w.query_rule(r1);

    println!("caveat 1 results:");
    for fact in res.iter() {
      println!("\t{}", syms.print_fact(fact));
    }

    assert!(!res.is_empty());

    let r2 = rule(caveat2, &[&file1], &[
                                pred(resource, &[&ambient, &file1])
    ]);
    //let res = w.query(pred(resource, &[ambient, sym(&mut syms, "file1")]));
    //
    println!("caveat 2: {}", syms.print_rule(&r2));
    let res = w.query_rule(r2);

    println!("caveat 2 results:");
    for fact in res.iter() {
      println!("\t{}", syms.print_fact(fact));
    }

    assert!(!res.is_empty());
  }

  #[test]
  fn revocation_id() {
    let mut syms = SymbolTable::new();
    let revocation_id = syms.insert("revocation_id");
    let valid_revocation_id = syms.insert("valid_revocation_id");

    let authority_facts = vec![];
    let authority_rules = vec![];
    let ambient_facts = vec![];
    let ambient_rules = vec![];


    let mut w = World::biscuit_create(&mut syms, authority_facts, authority_rules,
    ambient_facts, ambient_rules);

    let block_fact = fact(revocation_id, &[int(42)]);
    w.add_fact(block_fact);
    w.run();
    for fact in w.facts.iter() {
      println!("- {}", syms.print_fact(&fact));
    }

    let ambient_query = constrained_rule(valid_revocation_id, &[ID::Variable(42)],
      &[pred(revocation_id, &[&ID::Variable(42)])],
      &[Constraint { id: 42, kind: ConstraintKind::Int(IntConstraint::NotIn([0, 5, 12, 2000].iter().cloned().collect())) }]
    );

    println!("ambient query (revocation id): {}", syms.print_rule(&ambient_query));
    let res = w.query_rule(ambient_query);

    println!("ambient query results:");
    for fact in res.iter() {
      println!("\t{}", syms.print_fact(fact));
    }

    assert!(!res.is_empty());
  }

  /// example 2 from https://github.com/CleverCloud/biscuit/issues/11#issuecomment-460751989
  #[test]
  fn example2_authority_rules() {
    let mut syms = SymbolTable::new();
    let authority = syms.add("authority");
    let ambient = syms.add("ambient");
    let file1 = syms.add("file1");
    let read = syms.add("read");
    let write = syms.add("write");
    let geoffroy = syms.add("geoffroy");
    let right = syms.insert("right");
    let resource = syms.insert("resource");
    let operation = syms.insert("operation");
    let owner = syms.insert("owner");
    let caveat1 = syms.insert("caveat1");

    let authority_facts = vec![];
    let authority_rules = vec![
      rule(right, &[&authority, &var("X"), &read], &[
           pred(resource, &[&ambient, &var("X")]),
           pred(owner, &[&ambient, &var("Y"), &var("X")])
      ]),
      rule(right, &[&authority, &var("X"), &write], &[
           pred(resource, &[&ambient, &var("X")]),
           pred(owner, &[&ambient, &var("Y"), &var("X")])
      ]),
    ];
    let ambient_facts = vec![
      fact(resource, &[&ambient, &file1]),
      fact(operation, &[&ambient, &read]),
      fact(owner, &[&ambient, &geoffroy,&file1]),
    ];
    let ambient_rules = vec![];

    for fact in authority_facts.iter() {
      println!("{}", syms.print_fact(&fact));
    }
    for rule in authority_rules.iter() {
      println!("{}", syms.print_rule(&rule));
    }
    for fact in ambient_facts.iter() {
      println!("{}", syms.print_fact(&fact));
    }
    for rule in ambient_rules.iter() {
      println!("{}", syms.print_rule(&rule));
    }

    let w = World::biscuit_create(&mut syms, authority_facts, authority_rules,
    ambient_facts, ambient_rules);
    for fact in w.facts.iter() {
      println!("\t{}", syms.print_fact(fact));
    }

    let res = w.query_rule(rule(caveat1, &[var("X")], &[
                                pred(resource, &[&ambient, &var("X")]),
                                pred(owner, &[&ambient, &geoffroy, &var("X")])
    ]));

    println!("caveat 1 results:");
    for fact in res.iter() {
      println!("\t{}", syms.print_fact(fact));
    }

    assert!(!res.is_empty());
  }

  /// example 3 from https://github.com/CleverCloud/biscuit/issues/11#issuecomment-460813482
  #[test]
  fn example3_constraints() {
    let mut syms = SymbolTable::new();
    let authority = syms.add("authority");
    let ambient = syms.add("ambient");
    let read = syms.add("read");
    let right = syms.insert("right");
    let resource = syms.insert("resource");
    let operation = syms.insert("operation");
    let time = syms.insert("time");
    let source = syms.insert("source");
    let caveat1 = syms.insert("caveat1");
    let caveat2 = syms.insert("caveat2");
    let caveat3 = syms.insert("caveat3");

    let authority_facts = vec![
      fact(right, &[&authority, &string("/folder/file1"), &read]),
      fact(right, &[&authority, &string("/folder/file2"), &read]),
      fact(right, &[&authority, &string("/folder2/file3"), &read]),
    ];
    let authority_rules = vec![];
    let ambient_facts = vec![
      fact(resource, &[&ambient, &string("/folder/file1")]),
      fact(operation, &[&ambient, &read]),
      fact(time, &[&ambient, &date(&SystemTime::now())]),
      fact(source, &[&ambient, &string("192.168.1.3")]),
    ];
    let ambient_rules = vec![];

    for fact in authority_facts.iter() {
      println!("{}", syms.print_fact(&fact));
    }
    for rule in authority_rules.iter() {
      println!("{}", syms.print_rule(&rule));
    }
    for fact in ambient_facts.iter() {
      println!("{}", syms.print_fact(&fact));
    }
    for rule in ambient_rules.iter() {
      println!("{}", syms.print_rule(&rule));
    }

    let w = World::biscuit_create(&mut syms, authority_facts, authority_rules,
    ambient_facts, ambient_rules);

    // will expire on 2020-02-18 15:56:10GMT+01:00
    let expiration = 1582041370;

    // time caveat
    let r1 = constrained_rule(caveat1, &[ID::Variable(0)],
    &[
    pred(time, &[&ambient, &ID::Variable(0)]),
    ],
    &[Constraint {
      id: 0,
      kind: ConstraintKind::Date(DateConstraint::Before(expiration))
    }]
    );

    println!("caveat 1: {}", syms.print_rule(&r1));
    let res = w.query_rule(r1);

    assert!(!res.is_empty());

    // set inclusion caveat
    let r2 = constrained_rule(caveat2, &[ID::Variable(0)],
    &[
    pred(source, &[&ambient, &ID::Variable(0)]),
      ],
      &[Constraint {
        id: 0,
        kind: ConstraintKind::Str(StrConstraint::In(["1.2.3.4".to_string(), "192.168.1.3".to_string()].iter().cloned().collect()))
      }]
    );

    println!("caveat 2: {}", syms.print_rule(&r2));
    let res = w.query_rule(r2);

    assert!(!res.is_empty());

    // string prefix caveat
    let r3 = constrained_rule(caveat3, &[ID::Variable(1234)], &[
        pred(resource, &[ambient, ID::Variable(1234)]),
      ],
      &[Constraint {
        id: 1234,
        kind: ConstraintKind::Str(StrConstraint::Prefix("/folder/".to_string()))
      }]
    );

    println!("caveat 3: {}", syms.print_rule(&r3));
    let res = w.query_rule(r3);

    assert!(!res.is_empty());
  }

  /// example 4 from https://github.com/CleverCloud/biscuit/issues/11#issuecomment-460989277
  #[test]
  fn example4_multiple_verifiers() {
    let mut syms = SymbolTable::new();
    let authority = syms.add("authority");
    let ambient = syms.add("ambient");
    let myorg = syms.add("myorg");
    let myapp = syms.add("myapp");
    let myapp2 = syms.add("myapp2");
    let deploy = syms.add("deploy");
    let undeploy = syms.add("undeploy");
    let read_id = syms.insert("read");
    let write_id = syms.insert("write");
    let deploy_id = syms.insert("deploy");
    let right = syms.insert("right");
    let operation = syms.insert("operation");
    let organisation = syms.insert("organisation");
    let application = syms.insert("application");
    let owner = syms.insert("owner");
    let caveat1 = syms.insert("caveat1");

    let authority_facts = vec![
      fact(organisation, &[&authority, &myorg]),
      fact(owner, &[&authority, &myorg, &myapp]),
      fact(owner, &[&authority, &myorg, &myapp2]),
    ];
    let authority_rules = vec![
      // this rule will generate a right fact only if there's the correct combination of
      // authority and ambient facts
      constrained_rule(right, &[&authority, &var("X"), &ID::Variable(0)], &[
        pred(application, &[&ambient, &var("X")]),
        pred(owner, &[&authority, &myorg, &var("X")]),
        pred(operation, &[&ambient, &ID::Variable(0)]),
      ],
      &[
        Constraint {
          id: 0,
          kind: ConstraintKind::Symbol(SymbolConstraint::In([read_id, write_id, deploy_id].iter().cloned().collect()))
        }
      ]),
    ];

    let caveat1 = rule(caveat1, &[var("X")], &[
        pred(application, &[&ambient, &myapp]),
        pred(operation, &[&ambient, &var("X")]),
        pred(right, &[&authority, &myapp, &var("X")]),
      ],
    );

    {
      // Verifier1
      let ambient_facts1 = vec![
        fact(application, &[&ambient, &myapp]),
        fact(operation, &[&ambient, &deploy]),
      ];
      let ambient_rules1 = vec![];

      let mut syms1 = syms.clone();

      let w1 = World::biscuit_create(&mut syms1, authority_facts.clone(), authority_rules.clone(),
        ambient_facts1, ambient_rules1);
      for fact in w1.facts.iter() {
        println!("verifier 1: {}", syms1.print_fact(fact));
      }

      let res = w1.query_rule(caveat1.clone());

      println!("verifier 1, caveat 1 results:");
      for fact in res.iter() {
        println!("\t{}", syms1.print_fact(fact));
      }

      assert!(!res.is_empty());
    }

    {
      // Verifier2
      let ambient_facts2 = vec![
        fact(application, &[&ambient, &myapp]),
        fact(operation, &[&ambient, &undeploy]),
      ];
      let ambient_rules2 = vec![];

      let mut syms2 = syms.clone();

      let w2 = World::biscuit_create(&mut syms2, authority_facts.clone(), authority_rules.clone(),
        ambient_facts2, ambient_rules2);
      for fact in w2.facts.iter() {
        println!("verifier 2: {}", syms2.print_fact(fact));
      }

      let res = w2.query_rule(caveat1.clone());

      println!("verifier2, caveat 1 results:");
      for fact in res.iter() {
        println!("\t{}", syms2.print_fact(fact));
      }

      assert!(res.is_empty());
    }
  }
}

#[cfg(test)]
mod bench {
  use super::*;
  use test::Bencher;

  #[bench]
  fn example1_basic(bench: &mut Bencher) {
    let mut syms = SymbolTable::new();
    let authority = syms.add("authority");
    let ambient = syms.add("ambient");
    let file1 = syms.add("file1");
    let file2 = syms.add("file2");
    let read = syms.add("read");
    let write = syms.add("write");
    let right = syms.insert("right");
    let resource = syms.insert("resource");
    let operation = syms.insert("operation");
    let caveat1 = syms.insert("caveat1");
    let caveat2 = syms.insert("caveat2");

    let authority_facts = vec![
      fact(right, &[&authority, &file1, &read]),
      fact(right, &[&authority, &file2, &read]),
      fact(right, &[&authority, &file1, &write]),
    ];
    let authority_rules = vec![];
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
  }

  #[bench]
  fn example2_authority_rules(bench: &mut Bencher) {
    let mut syms = SymbolTable::new();
    let authority = syms.add("authority");
    let ambient = syms.add("ambient");
    let file1 = syms.add("file1");
    let read = syms.add("read");
    let write = syms.add("write");
    let geoffroy = syms.add("geoffroy");
    let right = syms.insert("right");
    let resource = syms.insert("resource");
    let operation = syms.insert("operation");
    let owner = syms.insert("owner");
    let caveat1 = syms.insert("caveat1");

    let authority_facts = vec![];
    let authority_rules = vec![
      rule(right, &[&authority, &var("X"), &read], &[
        pred(resource, &[&ambient, &var("X")]),
        pred(owner, &[&ambient, &var("Y"), &var("X")])
      ]),
      rule(right, &[&authority, &var("X"), &write], &[
        pred(resource, &[&ambient, &var("X")]),
        pred(owner, &[&ambient, &var("Y"), &var("X")])
      ]),
    ];
    let ambient_facts = vec![
      fact(resource, &[&ambient, &file1]),
      fact(operation, &[&ambient, &read]),
      fact(owner, &[&ambient, &geoffroy,&file1]),
    ];
    let ambient_rules = vec![];


    bench.iter(|| {
      let w = World::biscuit_create(&mut syms, authority_facts.clone(), authority_rules.clone(),
        ambient_facts.clone(), ambient_rules.clone());

      let res = w.query_rule(rule(caveat1, &[var("X")], &[
        pred(resource, &[&ambient, &var("X")]),
        pred(owner, &[&ambient, &geoffroy, &var("X")])
      ]));


      !res.is_empty()
    });
  }

  #[bench]
  fn example3_constraints(bench: &mut Bencher) {
    let mut syms = SymbolTable::new();
    let authority = syms.add("authority");
    let ambient = syms.add("ambient");
    let read = syms.add("read");
    let right = syms.insert("right");
    let time = syms.insert("time");
    let source = syms.insert("source");
    let resource = syms.insert("resource");
    let operation = syms.insert("operation");
    let caveat1 = syms.insert("caveat1");
    let caveat2 = syms.insert("caveat2");
    let caveat3 = syms.insert("caveat3");

    let authority_facts = vec![
      fact(right, &[&authority, &string("/folder/file1"), &read]),
      fact(right, &[&authority, &string("/folder/file2"), &read]),
      fact(right, &[&authority, &string("/folder2/file3"), &read]),
    ];
    let authority_rules = vec![];
    let ambient_facts = vec![
      fact(resource, &[&ambient, &string("/folder/file1")]),
      fact(operation, &[&ambient, &read]),
      fact(time, &[&ambient, &date(&SystemTime::now())]),
      fact(source, &[&ambient, &string("192.168.1.3")]),
    ];
    let ambient_rules = vec![];

    bench.iter(move || {
      let w = World::biscuit_create(&mut syms, authority_facts.clone(), authority_rules.clone(),
        ambient_facts.clone(), ambient_rules.clone());
      for fact in w.facts.iter() {
        println!("\t{}", syms.print_fact(fact));
      }

      // will expire on 2020-02-18 15:56:10GMT+01:00
      let expiration = 1582041370;

      // time caveat
      let res = w.query_rule(constrained_rule(caveat1, &[ID::Variable(0)],
        &[
          pred(time, &[&ambient, &ID::Variable(0)]),
        ],
        &[Constraint {
          id: 0,
          kind: ConstraintKind::Date(DateConstraint::Before(expiration))
        }]
      ));

      assert!(!res.is_empty());

      // set inclusion caveat
      let res = w.query_rule(constrained_rule(caveat2, &[ID::Variable(0)],
        &[
          pred(source, &[&ambient, &ID::Variable(0)]),
        ],
        &[Constraint {
          id: 0,
          kind: ConstraintKind::Str(StrConstraint::In(["1.2.3.4".to_string(), "192.168.1.3".to_string()].iter().cloned().collect()))
        }]
      ));

      assert!(!res.is_empty());

      // string prefix caveat
      let res = w.query_rule(constrained_rule(caveat3, &[ID::Variable(1234)], &[
          pred(resource, &[&ambient, &ID::Variable(1234)]),
        ],
        &[Constraint {
          id: 1234,
          kind: ConstraintKind::Str(StrConstraint::Prefix("/folder/".to_string()))
        }]
      ));

      assert!(!res.is_empty());
    });
  }
}
