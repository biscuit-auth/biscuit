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
    "revocation_id(0, hex:596a24631a8eeec5cbc0d84fc6c22fec1a524c7367bc8926827201ddd218f4bb)",
    "revocation_id(1, hex:dec4e0a7f817fe6c5964a18e9f0eae5564c12531b05dc4525f553570519baa87)",
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
    "revocation_id(0, hex:deaf1b539fda04436be70357d4dca8435581661e47d5a6b690054a9e7b63ed09)",
    "revocation_id(1, hex:e1ad30e387ff5b866bf631ac3c572256730cba0612d88054a863aa8c0702dbd6)",
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
    "revocation_id(0, hex:20262f14cd4d28aa7e95ec93e94c28faf9aac1e7b720fb47f177aea577b18691)",
    "revocation_id(1, hex:9065c0f8a4abad0c01877a2a9427e948688fbe296069eeef021179d5b936e260)",
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
    "revocation_id(0, hex:ea25b30574845105fb8def0856560d07182bf5ab14fd4d32040431a69d788534)",
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
    "revocation_id(0, hex:a5b6e79d15461ee3c304802c00dfa4237c3702f6dd8a1dd148a7b4dfba18ef40)",
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
    "revocation_id(0, hex:a5b6e79d15461ee3c304802c00dfa4237c3702f6dd8a1dd148a7b4dfba18ef40)",
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
                valid_date($1) <- time(#ambient, $0), resource(#ambient, $1), $0 <= 1999-12-31T12:59:59+00:00, !["file1"].contains($1)
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
    "revocation_id(0, hex:d6c50661f8f35fbfdc3daa70f6ca41608d628b245c91ba6d6281805aa9f47774)",
    "revocation_id(1, hex:c17a3b24a64978db6039d093f1109c63417b2dffc63b972abc69eb61ee28885e)",
    "right(#authority, \"file1\", #read)",
    "right(#authority, \"file2\", #read)",
    "time(#ambient, 2020-12-21T09:23:12+00:00)",
]
  rules: [
    "valid_date(\"file1\") <- time(#ambient, $0), resource(#ambient, \"file1\"), $0 <= 2030-12-31T12:59:59+00:00",
    "valid_date($1) <- time(#ambient, $0), resource(#ambient, $1), $0 <= 1999-12-31T12:59:59+00:00, ![\"file1\"].contains($1)",
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
    "revocation_id(0, hex:d6c50661f8f35fbfdc3daa70f6ca41608d628b245c91ba6d6281805aa9f47774)",
    "revocation_id(1, hex:c17a3b24a64978db6039d093f1109c63417b2dffc63b972abc69eb61ee28885e)",
    "right(#authority, \"file1\", #read)",
    "right(#authority, \"file2\", #read)",
    "time(#ambient, 2020-12-21T09:23:12+00:00)",
]
  rules: [
    "valid_date(\"file1\") <- time(#ambient, $0), resource(#ambient, \"file1\"), $0 <= 2030-12-31T12:59:59+00:00",
    "valid_date($1) <- time(#ambient, $0), resource(#ambient, $1), $0 <= 1999-12-31T12:59:59+00:00, ![\"file1\"].contains($1)",
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
    "revocation_id(0, hex:a3a87a95f62fe215a0a83d462b8bb0e8b030d7d4d933706d19c3461a85bd3e83)",
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
    "revocation_id(0, hex:a3a87a95f62fe215a0a83d462b8bb0e8b030d7d4d933706d19c3461a85bd3e83)",
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
    "revocation_id(0, hex:1ded979c6661e34b09cedf85c778ab0f0304e7c0ca44382348e76147cb1fa3f3)",
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
    "revocation_id(0, hex:8f03890eeaa997cd03da71115168e41425b2be82731026225b0c5b87163e4d8e)",
    "revocation_id(1, hex:94fff36a9fa4d4149ab1488bf4aa84ed0bab0075cc7d051270367fb9c9688795)",
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

------------------------------

## test expression syntax and all available operations: test17_expressions.bc
biscuit: Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "query", "abc", "hello", "world"]
    authority: Block[0] {
            symbols: ["query", "abc", "hello", "world"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if true,
                check if !false,
                check if !false,
                check if false or true,
                check if 1 < 2,
                check if 2 > 1,
                check if 1 <= 2,
                check if 1 <= 1,
                check if 2 >= 1,
                check if 2 >= 2,
                check if 3 == 3,
                check if 1 + 2 * 3 - 4 / 2 == 5,
                check if "hello world".starts_with("hello") && "hello world".ends_with("world"),
                check if "aaabde".matches("a*c?.e"),
                check if "abcD12" == "abcD12",
                check if 2019-12-04T09:46:41+00:00 < 2020-12-04T09:46:41+00:00,
                check if 2020-12-04T09:46:41+00:00 > 2019-12-04T09:46:41+00:00,
                check if 2019-12-04T09:46:41+00:00 <= 2020-12-04T09:46:41+00:00,
                check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00,
                check if 2020-12-04T09:46:41+00:00 >= 2019-12-04T09:46:41+00:00,
                check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00,
                check if 2020-12-04T09:46:41+00:00 == 2020-12-04T09:46:41+00:00,
                check if #abc == #abc,
                check if hex:12ab == hex:12ab,
                check if [1, 2].contains(2),
                check if [2019-12-04T09:46:41+00:00, 2020-12-04T09:46:41+00:00].contains(2020-12-04T09:46:41+00:00),
                check if [false, true].contains(true),
                check if ["abc", "def"].contains("abc"),
                check if [hex:12ab, hex:34de].contains(hex:34de),
                check if [#hello, #world].contains(#hello)
            ]
        }
    blocks: [
        
    ]
}
verifier world:
World {
  facts: [
    "revocation_id(0, hex:d3258e24583d1482da74b2a4864074428659ebd7f5c35d42d97ce33b3f32f59d)",
]
  rules: []
  checks: [
    "Block[0][0]: check if true",
    "Block[0][1]: check if !false",
    "Block[0][2]: check if !false",
    "Block[0][3]: check if false or true",
    "Block[0][4]: check if 1 < 2",
    "Block[0][5]: check if 2 > 1",
    "Block[0][6]: check if 1 <= 2",
    "Block[0][7]: check if 1 <= 1",
    "Block[0][8]: check if 2 >= 1",
    "Block[0][9]: check if 2 >= 2",
    "Block[0][10]: check if 3 == 3",
    "Block[0][11]: check if 1 + 2 * 3 - 4 / 2 == 5",
    "Block[0][12]: check if \"hello world\".starts_with(\"hello\") && \"hello world\".ends_with(\"world\")",
    "Block[0][13]: check if \"aaabde\".matches(\"a*c?.e\")",
    "Block[0][14]: check if \"abcD12\" == \"abcD12\"",
    "Block[0][15]: check if 2019-12-04T09:46:41+00:00 < 2020-12-04T09:46:41+00:00",
    "Block[0][16]: check if 2020-12-04T09:46:41+00:00 > 2019-12-04T09:46:41+00:00",
    "Block[0][17]: check if 2019-12-04T09:46:41+00:00 <= 2020-12-04T09:46:41+00:00",
    "Block[0][18]: check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00",
    "Block[0][19]: check if 2020-12-04T09:46:41+00:00 >= 2019-12-04T09:46:41+00:00",
    "Block[0][20]: check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00",
    "Block[0][21]: check if 2020-12-04T09:46:41+00:00 == 2020-12-04T09:46:41+00:00",
    "Block[0][22]: check if #abc == #abc",
    "Block[0][23]: check if hex:12ab == hex:12ab",
    "Block[0][24]: check if [1, 2].contains(2)",
    "Block[0][25]: check if [2019-12-04T09:46:41+00:00, 2020-12-04T09:46:41+00:00].contains(2020-12-04T09:46:41+00:00)",
    "Block[0][26]: check if [false, true].contains(true)",
    "Block[0][27]: check if [\"abc\", \"def\"].contains(\"abc\")",
    "Block[0][28]: check if [hex:12ab, hex:34de].contains(hex:34de)",
    "Block[0][29]: check if [#hello, #world].contains(#hello)",
]
  policies: [
    "allow if true",
]
}
validation: `Ok(())`
