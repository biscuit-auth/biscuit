# Biscuit samples and expected results

root secret key: 79a33df5e9912e3fa1b7b7d87275c58dc7e8348f45ae783a5aaaf3bceb6bb10e
root public key: 529e780f28d9181c968b0eab9977ed8494a27a4544c3adc1910f41bb3dc36958

------------------------------

## basic token: test1_basic.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "check1", "0"]
    authority: Block[0] {
            symbols: ["read", "write"]
            version: 1
            context: ""
            facts: [
                right(#authority, "file1", #read),
                right(#authority, "file2", #read),
                right(#authority, "file1", #write)
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block[1] {
            symbols: ["check1", "0"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)
            ]
        }
    ]
}
```

verifier world:
World {
  facts: [
    "resource(#ambient, \"file1\")",
    "right(#authority, \"file1\", #read)",
    "right(#authority, \"file1\", #write)",
    "right(#authority, \"file2\", #read)",
]
  rules: []
  checks: [
    "Block[1][0]: check if resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)",
]
  policies: [
    "allow if true",
]
}
validation: `Err(FailedLogic(FailedChecks([Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)" })])))`

------------------------------

## different root key: test2_different_root_key.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "check1", "0"]
    authority: Block[0] {
            symbols: ["read"]
            version: 1
            context: ""
            facts: [
                right(#authority, "file1", #read)
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block[1] {
            symbols: ["check1", "0"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)
            ]
        }
    ]
}
```

validation: `Err(Format(UnknownPublicKey))`

------------------------------

## invalid signature format: test3_invalid_signature_format.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "check1", "0"]
    authority: Block[0] {
            symbols: ["read", "write"]
            version: 1
            context: ""
            facts: [
                right(#authority, "file1", #read),
                right(#authority, "file2", #read),
                right(#authority, "file1", #write)
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block[1] {
            symbols: ["check1", "0"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)
            ]
        }
    ]
}
```

validation: `Err(Format(DeserializationError("deserialization error: invalid size for z = 16 bytes")))`

------------------------------

## random block: test4_random_block.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "check1", "0"]
    authority: Block[0] {
            symbols: ["read", "write"]
            version: 1
            context: ""
            facts: [
                right(#authority, "file1", #read),
                right(#authority, "file2", #read),
                right(#authority, "file1", #write)
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block[1] {
            symbols: ["check1", "0"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)
            ]
        }
    ]
}
```

validation: `Err(Format(Signature(InvalidSignature)))`

------------------------------

## invalid signature: test5_invalid_signature.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "check1", "0"]
    authority: Block[0] {
            symbols: ["read", "write"]
            version: 1
            context: ""
            facts: [
                right(#authority, "file1", #read),
                right(#authority, "file2", #read),
                right(#authority, "file1", #write)
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block[1] {
            symbols: ["check1", "0"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)
            ]
        }
    ]
}
```

validation: `Err(Format(Signature(InvalidSignature)))`

------------------------------

## reordered blocks: test6_reordered_blocks.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "check1", "0"]
    authority: Block[0] {
            symbols: ["read", "write"]
            version: 1
            context: ""
            facts: [
                right(#authority, "file1", #read),
                right(#authority, "file2", #read),
                right(#authority, "file1", #write)
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block[1] {
            symbols: ["check1", "0"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)
            ]
        }
    ]
}
```

validation: `Err(InvalidBlockIndex(InvalidBlockIndex { expected: 1, found: 2 }))`

------------------------------

## invalid block fact with authority tag: test7_invalid_block_fact_authority.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "check1", "0"]
    authority: Block[0] {
            symbols: ["read"]
            version: 1
            context: ""
            facts: [
                right(#authority, "file1", #read)
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block[1] {
            symbols: ["write", "check1", "0"]
            version: 1
            context: ""
            facts: [
                right(#authority, "file1", #write)
            ]
            rules: []
            checks: [
                check if operation(#ambient, #read)
            ]
        }
    ]
}
```

validation: `Err(FailedLogic(InvalidBlockFact(0, "right(#authority, \"file1\", #write)")))`

------------------------------

## invalid block fact with ambient tag: test8_invalid_block_fact_ambient.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "check1", "0"]
    authority: Block[0] {
            symbols: ["read"]
            version: 1
            context: ""
            facts: [
                right(#authority, "file1", #read)
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block[1] {
            symbols: ["write", "check1", "0"]
            version: 1
            context: ""
            facts: [
                right(#ambient, "file1", #write)
            ]
            rules: []
            checks: [
                check if operation(#ambient, #read)
            ]
        }
    ]
}
```

validation: `Err(FailedLogic(InvalidBlockFact(0, "right(#ambient, \"file1\", #write)")))`

------------------------------

## expired token: test9_expired_token.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "check1", "expiration", "date", "time"]
    authority: Block[0] {
            symbols: []
            version: 1
            context: ""
            facts: []
            rules: []
            checks: []
        }
    blocks: [
        Block[1] {
            symbols: ["check1", "expiration", "date", "time"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if resource(#ambient, "file1"),
                check if time(#ambient, $date), $date <= 2018-12-20T00:00:00+00:00
            ]
        }
    ]
}
```

verifier world:
World {
  facts: [
    "operation(#ambient, #read)",
    "resource(#ambient, \"file1\")",
    "time(#ambient, 2020-12-21T09:23:12+00:00)",
]
  rules: []
  checks: [
    "Block[1][0]: check if resource(#ambient, \"file1\")",
    "Block[1][1]: check if time(#ambient, $date), $date <= 2018-12-20T00:00:00+00:00",
]
  policies: [
    "allow if true",
]
}
validation: `Err(FailedLogic(FailedChecks([Block(FailedBlockCheck { block_id: 1, check_id: 1, rule: "check if time(#ambient, $date), $date <= 2018-12-20T00:00:00+00:00" })])))`

------------------------------

## authority rules: test10_authority_rules.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "1", "read", "owner", "0", "write", "check1", "check2", "alice"]
    authority: Block[0] {
            symbols: ["1", "read", "owner", "0", "write"]
            version: 1
            context: ""
            facts: []
            rules: [
                right(#authority, $1, #read) <- resource(#ambient, $1), owner(#ambient, $0, $1),
                right(#authority, $1, #write) <- resource(#ambient, $1), owner(#ambient, $0, $1)
            ]
            checks: []
        }
    blocks: [
        Block[1] {
            symbols: ["check1", "check2", "alice"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if right(#authority, $0, $1), resource(#ambient, $0), operation(#ambient, $1),
                check if resource(#ambient, $0), owner(#ambient, #alice, $0)
            ]
        }
    ]
}
```

verifier world:
World {
  facts: [
    "operation(#ambient, #read)",
    "owner(#ambient, #alice, \"file1\")",
    "resource(#ambient, \"file1\")",
]
  rules: [
    "right(#authority, $1, #read) <- resource(#ambient, $1), owner(#ambient, $0, $1)",
    "right(#authority, $1, #write) <- resource(#ambient, $1), owner(#ambient, $0, $1)",
]
  checks: [
    "Block[1][0]: check if right(#authority, $0, $1), resource(#ambient, $0), operation(#ambient, $1)",
    "Block[1][1]: check if resource(#ambient, $0), owner(#ambient, #alice, $0)",
]
  policies: [
    "allow if true",
]
}
validation: `Ok(())`

------------------------------

## verifier authority checks: test11_verifier_authority_caveats.bc
biscuit:
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read"]
    authority: Block[0] {
            symbols: ["read"]
            version: 1
            context: ""
            facts: [
                right(#authority, "file1", #read)
            ]
            rules: []
            checks: []
        }
    blocks: [
        
    ]
}
```

verifier world:
World {
  facts: [
    "operation(#ambient, #read)",
    "resource(#ambient, \"file2\")",
    "right(#authority, \"file1\", #read)",
]
  rules: []
  checks: [
    "Verifier[0]: check if right(#authority, $0, $1), resource(#ambient, $0), operation(#ambient, $1)",
]
  policies: [
    "allow if true",
]
}
validation: `Err(FailedLogic(FailedChecks([Verifier(FailedVerifierCheck { check_id: 0, rule: "check if right(#authority, $0, $1), resource(#ambient, $0), operation(#ambient, $1)" })])))`

------------------------------

## authority checks: test12_authority_caveats.bc
biscuit:
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "check1"]
    authority: Block[0] {
            symbols: ["check1"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if resource(#ambient, "file1")
            ]
        }
    blocks: [
        
    ]
}
```

verifier world:
World {
  facts: [
    "operation(#ambient, #read)",
    "resource(#ambient, \"file1\")",
]
  rules: []
  checks: [
    "Block[0][0]: check if resource(#ambient, \"file1\")",
]
  policies: [
    "allow if true",
]
}
validation for "file1": `Ok(())`
verifier world:
World {
  facts: [
    "operation(#ambient, #read)",
    "resource(#ambient, \"file2\")",
]
  rules: []
  checks: [
    "Block[0][0]: check if resource(#ambient, \"file1\")",
]
  policies: [
    "allow if true",
]
}
validation for "file2": `Err(FailedLogic(FailedChecks([Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if resource(#ambient, \"file1\")" })])))`

------------------------------

## block rules: test13_block_rules.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "valid_date", "time", "0", "1", "check1"]
    authority: Block[0] {
            symbols: ["read"]
            version: 1
            context: ""
            facts: [
                right(#authority, "file1", #read),
                right(#authority, "file2", #read)
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block[1] {
            symbols: ["valid_date", "time", "0", "1", "check1"]
            version: 1
            context: ""
            facts: []
            rules: [
                valid_date("file1") <- time(#ambient, $0), resource(#ambient, "file1"), $0 <= 2030-12-31T12:59:59+00:00,
                valid_date($1) <- time(#ambient, $0), resource(#ambient, $1), $0 <= 1999-12-31T12:59:59+00:00, !$1.contains(["\"file1\""])
            ]
            checks: [
                check if valid_date($0), resource(#ambient, $0)
            ]
        }
    ]
}
```

verifier world:
World {
  facts: [
    "resource(#ambient, \"file1\")",
    "right(#authority, \"file1\", #read)",
    "right(#authority, \"file2\", #read)",
    "time(#ambient, 2020-12-21T09:23:12+00:00)",
]
  rules: [
    "valid_date(\"file1\") <- time(#ambient, $0), resource(#ambient, \"file1\"), $0 <= 2030-12-31T12:59:59+00:00",
    "valid_date($1) <- time(#ambient, $0), resource(#ambient, $1), $0 <= 1999-12-31T12:59:59+00:00, !$1.contains([\"\\\"file1\\\"\"])",
]
  checks: [
    "Block[1][0]: check if valid_date($0), resource(#ambient, $0)",
]
  policies: [
    "allow if true",
]
}
validation for "file1": `Ok(())`
verifier world:
World {
  facts: [
    "resource(#ambient, \"file2\")",
    "right(#authority, \"file1\", #read)",
    "right(#authority, \"file2\", #read)",
    "time(#ambient, 2020-12-21T09:23:12+00:00)",
]
  rules: [
    "valid_date(\"file1\") <- time(#ambient, $0), resource(#ambient, \"file1\"), $0 <= 2030-12-31T12:59:59+00:00",
    "valid_date($1) <- time(#ambient, $0), resource(#ambient, $1), $0 <= 1999-12-31T12:59:59+00:00, !$1.contains([\"\\\"file1\\\"\"])",
]
  checks: [
    "Block[1][0]: check if valid_date($0), resource(#ambient, $0)",
]
  policies: [
    "allow if true",
]
}
validation for "file2": `Err(FailedLogic(FailedChecks([Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if valid_date($0), resource(#ambient, $0)" })])))`

------------------------------

## regex_constraint: test14_regex_constraint.bc
biscuit:
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "resource_match", "0"]
    authority: Block[0] {
            symbols: ["resource_match", "0"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if resource(#ambient, $0), $0.matches("file[0-9]+.txt")
            ]
        }
    blocks: [
        
    ]
}
```

verifier world:
World {
  facts: [
    "resource(#ambient, \"file1\")",
]
  rules: []
  checks: [
    "Block[0][0]: check if resource(#ambient, $0), $0.matches(\"file[0-9]+.txt\")",
]
  policies: [
    "allow if true",
]
}
validation for "file1": `Err(FailedLogic(FailedChecks([Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if resource(#ambient, $0), $0.matches(\"file[0-9]+.txt\")" })])))`
verifier world:
World {
  facts: [
    "resource(#ambient, \"file123.txt\")",
]
  rules: []
  checks: [
    "Block[0][0]: check if resource(#ambient, $0), $0.matches(\"file[0-9]+.txt\")",
]
  policies: [
    "allow if true",
]
}
validation for "file123.txt": `Ok(())`

------------------------------

## multi queries checks: test15_multi_queries_caveats.bc
biscuit:
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "must_be_present"]
    authority: Block[0] {
            symbols: ["must_be_present"]
            version: 1
            context: ""
            facts: [
                must_be_present(#authority, "hello")
            ]
            rules: []
            checks: []
        }
    blocks: [
        
    ]
}
```

verifier world:
World {
  facts: [
    "must_be_present(#authority, \"hello\")",
]
  rules: []
  checks: [
    "Verifier[0]: check if must_be_present(#authority, $0) or must_be_present($0)",
]
  policies: [
    "allow if true",
]
}
validation: `Ok(())`

------------------------------

## check head name should be independent from fact names: test16_caveat_head_name.bc
biscuit: Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "check1", "test", "hello"]
    authority: Block[0] {
            symbols: ["check1", "test", "hello"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if resource(#ambient, #hello)
            ]
        }
    blocks: [
        Block[1] {
            symbols: []
            version: 1
            context: ""
            facts: [
                check1(#test)
            ]
            rules: []
            checks: []
        }
    ]
}
verifier world:
World {
  facts: [
    "check1(#test)",
]
  rules: []
  checks: [
    "Block[0][0]: check if resource(#ambient, #hello)",
]
  policies: [
    "allow if true",
]
}
validation: `Err(FailedLogic(FailedChecks([Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if resource(#ambient, #hello)" })])))`
