# Biscuit samples and expected results

root secret key: 79a33df5e9912e3fa1b7b7d87275c58dc7e8348f45ae783a5aaaf3bceb6bb10e
root public key: 529e780f28d9181c968b0eab9977ed8494a27a4544c3adc1910f41bb3dc36958

------------------------------

## basic token: test1_basic.bc
biscuit2 (1 caveat):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "caveat1", "0"]
    authority: Block[0] {
            symbols: ["read", "write"]
            context: ""
            facts: [
                right(#authority, "file1", #read),
                right(#authority, "file2", #read),
                right(#authority, "file1", #write)
            ]
            rules: []
            caveats: []
        }
    blocks: [
        Block[1] {
            symbols: ["caveat1", "0"]
            context: ""
            facts: []
            rules: []
            caveats: [
                caveat1($0) <- resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)
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
  caveats: [
    "Block[1][0]: caveat1($0) <- resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)",
]
}
validation: `Err(FailedLogic(FailedCaveats([Block(FailedBlockCaveat { block_id: 1, caveat_id: 0, rule: "caveat1($0) <- resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)" })])))`

------------------------------

## different root key: test2_different_root_key.bc
biscuit2 (1 caveat):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "caveat1", "0"]
    authority: Block[0] {
            symbols: ["read"]
            context: ""
            facts: [
                right(#authority, "file1", #read)
            ]
            rules: []
            caveats: []
        }
    blocks: [
        Block[1] {
            symbols: ["caveat1", "0"]
            context: ""
            facts: []
            rules: []
            caveats: [
                caveat1($0) <- resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)
            ]
        }
    ]
}
```

validation: `Err(Format(UnknownPublicKey))`

------------------------------

## invalid signature format: test3_invalid_signature_format.bc
biscuit2 (1 caveat):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "caveat1", "0"]
    authority: Block[0] {
            symbols: ["read", "write"]
            context: ""
            facts: [
                right(#authority, "file1", #read),
                right(#authority, "file2", #read),
                right(#authority, "file1", #write)
            ]
            rules: []
            caveats: []
        }
    blocks: [
        Block[1] {
            symbols: ["caveat1", "0"]
            context: ""
            facts: []
            rules: []
            caveats: [
                caveat1($0) <- resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)
            ]
        }
    ]
}
```

validation: `Err(Format(DeserializationError("deserialization error: invalid size for z = 16 bytes")))`

------------------------------

## random block: test4_random_block.bc
biscuit2 (1 caveat):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "caveat1", "0"]
    authority: Block[0] {
            symbols: ["read", "write"]
            context: ""
            facts: [
                right(#authority, "file1", #read),
                right(#authority, "file2", #read),
                right(#authority, "file1", #write)
            ]
            rules: []
            caveats: []
        }
    blocks: [
        Block[1] {
            symbols: ["caveat1", "0"]
            context: ""
            facts: []
            rules: []
            caveats: [
                caveat1($0) <- resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)
            ]
        }
    ]
}
```

validation: `Err(Format(Signature(InvalidSignature)))`

------------------------------

## invalid signature: test5_invalid_signature.bc
biscuit2 (1 caveat):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "caveat1", "0"]
    authority: Block[0] {
            symbols: ["read", "write"]
            context: ""
            facts: [
                right(#authority, "file1", #read),
                right(#authority, "file2", #read),
                right(#authority, "file1", #write)
            ]
            rules: []
            caveats: []
        }
    blocks: [
        Block[1] {
            symbols: ["caveat1", "0"]
            context: ""
            facts: []
            rules: []
            caveats: [
                caveat1($0) <- resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)
            ]
        }
    ]
}
```

validation: `Err(Format(Signature(InvalidSignature)))`

------------------------------

## reordered blocks: test6_reordered_blocks.bc
biscuit2 (1 caveat):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "caveat1", "0"]
    authority: Block[0] {
            symbols: ["read", "write"]
            context: ""
            facts: [
                right(#authority, "file1", #read),
                right(#authority, "file2", #read),
                right(#authority, "file1", #write)
            ]
            rules: []
            caveats: []
        }
    blocks: [
        Block[1] {
            symbols: ["caveat1", "0"]
            context: ""
            facts: []
            rules: []
            caveats: [
                caveat1($0) <- resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)
            ]
        }
    ]
}
```

validation: `Err(InvalidBlockIndex(InvalidBlockIndex { expected: 1, found: 2 }))`

------------------------------

## invalid block fact with authority tag: test7_invalid_block_fact_authority.bc
biscuit2 (1 caveat):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "caveat1", "0"]
    authority: Block[0] {
            symbols: ["read"]
            context: ""
            facts: [
                right(#authority, "file1", #read)
            ]
            rules: []
            caveats: []
        }
    blocks: [
        Block[1] {
            symbols: ["write", "caveat1", "0"]
            context: ""
            facts: [
                right(#authority, "file1", #write)
            ]
            rules: []
            caveats: [
                caveat1($0) <- operation(#ambient, #read)
            ]
        }
    ]
}
```

validation: `Err(FailedLogic(InvalidBlockFact(0, "right(#authority, \"file1\", #write)")))`

------------------------------

## invalid block fact with ambient tag: test8_invalid_block_fact_ambient.bc
biscuit2 (1 caveat):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "caveat1", "0"]
    authority: Block[0] {
            symbols: ["read"]
            context: ""
            facts: [
                right(#authority, "file1", #read)
            ]
            rules: []
            caveats: []
        }
    blocks: [
        Block[1] {
            symbols: ["write", "caveat1", "0"]
            context: ""
            facts: [
                right(#ambient, "file1", #write)
            ]
            rules: []
            caveats: [
                caveat1($0) <- operation(#ambient, #read)
            ]
        }
    ]
}
```

validation: `Err(FailedLogic(InvalidBlockFact(0, "right(#ambient, \"file1\", #write)")))`

------------------------------

## expired token: test9_expired_token.bc
biscuit2 (1 caveat):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "caveat1", "expiration", "date", "time"]
    authority: Block[0] {
            symbols: []
            context: ""
            facts: []
            rules: []
            caveats: []
        }
    blocks: [
        Block[1] {
            symbols: ["caveat1", "expiration", "date", "time"]
            context: ""
            facts: []
            rules: []
            caveats: [
                caveat1("file1") <- resource(#ambient, "file1"),
                expiration($date) <- time(#ambient, $date) @ $date <= 2018-12-20T00:00:00+00:00
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
    "time(#ambient, SystemTime { tv_sec: 1608542592, tv_nsec: 0 })",
]
  rules: []
  caveats: [
    "Block[1][0]: caveat1(\"file1\") <- resource(#ambient, \"file1\")",
    "Block[1][1]: expiration($date) <- time(#ambient, $date) @ $date <= 2018-12-20T00:00:00+00:00",
]
}
validation: `Err(FailedLogic(FailedCaveats([Block(FailedBlockCaveat { block_id: 1, caveat_id: 1, rule: "expiration($date) <- time(#ambient, $date) @ $date <= 2018-12-20T00:00:00+00:00" })])))`

------------------------------

## authority rules: test10_authority_rules.bc
biscuit2 (1 caveat):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "1", "read", "owner", "0", "write", "caveat1", "caveat2", "alice"]
    authority: Block[0] {
            symbols: ["1", "read", "owner", "0", "write"]
            context: ""
            facts: []
            rules: [
                right(#authority, $1, #read) <- resource(#ambient, $1), owner(#ambient, $0, $1),
                right(#authority, $1, #write) <- resource(#ambient, $1), owner(#ambient, $0, $1)
            ]
            caveats: []
        }
    blocks: [
        Block[1] {
            symbols: ["caveat1", "caveat2", "alice"]
            context: ""
            facts: []
            rules: []
            caveats: [
                caveat1($0, $1) <- right(#authority, $0, $1), resource(#ambient, $0), operation(#ambient, $1),
                caveat2($0) <- resource(#ambient, $0), owner(#ambient, #alice, $0)
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
  caveats: [
    "Block[1][0]: caveat1($0, $1) <- right(#authority, $0, $1), resource(#ambient, $0), operation(#ambient, $1)",
    "Block[1][1]: caveat2($0) <- resource(#ambient, $0), owner(#ambient, #alice, $0)",
]
}
validation: `Ok(())`

------------------------------

## verifier authority caveats: test11_verifier_authority_caveats.bc
biscuit:
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read"]
    authority: Block[0] {
            symbols: ["read"]
            context: ""
            facts: [
                right(#authority, "file1", #read)
            ]
            rules: []
            caveats: []
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
  caveats: [
    "Verifier[0]: *caveat1($0, $1) <- right(#authority, $0, $1), resource(#ambient, $0), operation(#ambient, $1)",
]
}
validation: `Err(FailedLogic(FailedCaveats([Verifier(FailedVerifierCaveat { caveat_id: 0, rule: "caveat1($0, $1) <- right(#authority, $0, $1), resource(#ambient, $0), operation(#ambient, $1)" })])))`

------------------------------

## authority caveats: test12_authority_caveats.bc
biscuit:
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "caveat1"]
    authority: Block[0] {
            symbols: ["caveat1"]
            context: ""
            facts: []
            rules: []
            caveats: [
                caveat1("file1") <- resource(#ambient, "file1")
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
  caveats: [
    "Block[0][0]: caveat1(\"file1\") <- resource(#ambient, \"file1\")",
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
  caveats: [
    "Block[0][0]: caveat1(\"file1\") <- resource(#ambient, \"file1\")",
]
}
validation for "file2": `Err(FailedLogic(FailedCaveats([Block(FailedBlockCaveat { block_id: 0, caveat_id: 0, rule: "caveat1(\"file1\") <- resource(#ambient, \"file1\")" })])))`

------------------------------

## block rules: test13_block_rules.bc
biscuit2 (1 caveat):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "valid_date", "time", "0", "1", "caveat1"]
    authority: Block[0] {
            symbols: ["read"]
            context: ""
            facts: [
                right(#authority, "file1", #read),
                right(#authority, "file2", #read)
            ]
            rules: []
            caveats: []
        }
    blocks: [
        Block[1] {
            symbols: ["valid_date", "time", "0", "1", "caveat1"]
            context: ""
            facts: []
            rules: [
                valid_date("file1") <- time(#ambient, $0), resource(#ambient, "file1") @ $0 <= 2030-12-31T12:59:59+00:00,
                valid_date($1) <- time(#ambient, $0), resource(#ambient, $1) @ $0 <= 1999-12-31T12:59:59+00:00, $1 not in {"file1"}
            ]
            caveats: [
                caveat1($0) <- valid_date($0), resource(#ambient, $0)
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
    "time(#ambient, SystemTime { tv_sec: 1608542592, tv_nsec: 0 })",
]
  rules: [
    "valid_date(\"file1\") <- time(#ambient, $0), resource(#ambient, \"file1\") @ $0 <= 2030-12-31T12:59:59+00:00",
    "valid_date($1) <- time(#ambient, $0), resource(#ambient, $1) @ $0 <= 1999-12-31T12:59:59+00:00, $1 not in {\"file1\"}",
]
  caveats: [
    "Block[1][0]: caveat1($0) <- valid_date($0), resource(#ambient, $0)",
]
}
validation for "file1": `Ok(())`
verifier world:
World {
  facts: [
    "resource(#ambient, \"file2\")",
    "right(#authority, \"file1\", #read)",
    "right(#authority, \"file2\", #read)",
    "time(#ambient, SystemTime { tv_sec: 1608542592, tv_nsec: 0 })",
]
  rules: [
    "valid_date(\"file1\") <- time(#ambient, $0), resource(#ambient, \"file1\") @ $0 <= 2030-12-31T12:59:59+00:00",
    "valid_date($1) <- time(#ambient, $0), resource(#ambient, $1) @ $0 <= 1999-12-31T12:59:59+00:00, $1 not in {\"file1\"}",
]
  caveats: [
    "Block[1][0]: caveat1($0) <- valid_date($0), resource(#ambient, $0)",
]
}
validation for "file2": `Err(FailedLogic(FailedCaveats([Block(FailedBlockCaveat { block_id: 1, caveat_id: 0, rule: "caveat1($0) <- valid_date($0), resource(#ambient, $0)" })])))`

------------------------------

## regex_constraint: test14_regex_constraint.bc
biscuit:
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "resource_match", "0"]
    authority: Block[0] {
            symbols: ["resource_match", "0"]
            context: ""
            facts: []
            rules: []
            caveats: [
                resource_match($0) <- resource(#ambient, $0) @ $0 matches /file[0-9]+.txt/
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
  caveats: [
    "Block[0][0]: resource_match($0) <- resource(#ambient, $0) @ $0 matches /file[0-9]+.txt/",
]
}
validation for "file1": `Err(FailedLogic(FailedCaveats([Block(FailedBlockCaveat { block_id: 0, caveat_id: 0, rule: "resource_match($0) <- resource(#ambient, $0) @ $0 matches /file[0-9]+.txt/" })])))`
verifier world:
World {
  facts: [
    "resource(#ambient, \"file123.txt\")",
]
  rules: []
  caveats: [
    "Block[0][0]: resource_match($0) <- resource(#ambient, $0) @ $0 matches /file[0-9]+.txt/",
]
}
validation for "file123.txt": `Ok(())`

------------------------------

## multi queries caveats: test15_multi_queries_caveats.bc
biscuit:
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "must_be_present"]
    authority: Block[0] {
            symbols: ["must_be_present"]
            context: ""
            facts: [
                must_be_present(#authority, "hello")
            ]
            rules: []
            caveats: []
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
  caveats: [
    "Verifier[0]: *test_must_be_present_authority($0) <- must_be_present(#authority, $0) || *test_must_be_present($0) <- must_be_present($0)",
]
}
validation: `Ok(())`

------------------------------

## caveat head name should be independent from fact names: test16_caveat_head_name.bc
biscuit: Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "caveat1", "test", "hello"]
    authority: Block[0] {
            symbols: ["caveat1", "test", "hello"]
            context: ""
            facts: []
            rules: []
            caveats: [
                caveat1(#test) <- resource(#ambient, #hello)
            ]
        }
    blocks: [
        Block[1] {
            symbols: []
            context: ""
            facts: [
                caveat1(#test)
            ]
            rules: []
            caveats: []
        }
    ]
}
verifier world:
World {
  facts: [
    "caveat1(#test)",
]
  rules: []
  caveats: [
    "Block[0][0]: caveat1(#test) <- resource(#ambient, #hello)",
]
}
validation: `Err(FailedLogic(FailedCaveats([Block(FailedBlockCaveat { block_id: 0, caveat_id: 0, rule: "caveat1(#test) <- resource(#ambient, #hello)" })])))`
