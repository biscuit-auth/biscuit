# Biscuit samples and expected results

root secret key: 12aca40167fbdd1a11037e9fd440e3d510d9d9dea70a6646aa4aaf84d718d75a
root public key: acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189

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

validation:
verifier world:
World {
  facts: {
    "resource(#ambient, \"file1\")",
    "revocation_id(0, hex:415b9d4bcfbcc052eb30b66bed5151a7291bd3ededa8679140753f97d9a0b3e6)",
    "revocation_id(1, hex:057ef57833aac9fb405ba1abadca1b088f2557700ea2004c79004ea688abeb47)",
    "right(#authority, \"file1\", #read)",
    "right(#authority, \"file1\", #write)",
    "right(#authority, \"file2\", #read)",
    "unique_revocation_id(0, hex:415b9d4bcfbcc052eb30b66bed5151a7291bd3ededa8679140753f97d9a0b3e6)",
    "unique_revocation_id(1, hex:057ef57833aac9fb405ba1abadca1b088f2557700ea2004c79004ea688abeb47)",
}
  privileged rules: {}
  rules: {}
  checks: {
    "check if resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)",
}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: \"check if resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)\" })"])


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

validation:
Err(["Format(Signature(InvalidSignature(\"signature error\")))"])


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

validation:
Err(["Format(InvalidSignatureSize(16))"])


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

validation:
Err(["Format(Signature(InvalidSignature(\"signature error\")))"])


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

validation:
Err(["Format(Signature(InvalidSignature(\"signature error\")))"])


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

biscuit3 (2 checks):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "check1", "0", "check2"]
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
        },
	Block[2] {
            symbols: ["check2"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if resource(#ambient, "file1")
            ]
        }
    ]
}
```

validation:
Err(["Format(Signature(InvalidSignature(\"signature error\")))"])


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

validation:
Err(["FailedLogic(InvalidBlockFact(0, \"right(#authority, \\\"file1\\\", #write)\"))"])


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

validation:
Err(["FailedLogic(InvalidBlockFact(0, \"right(#ambient, \\\"file1\\\", #write)\"))"])


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

validation:
verifier world:
World {
  facts: {
    "operation(#ambient, #read)",
    "resource(#ambient, \"file1\")",
    "revocation_id(0, hex:96123a8ee182336c4c63ad29f2b23549020da2a90841ac63ccec4c20413753b0)",
    "revocation_id(1, hex:60e6f54cb7a20ee0859495abe176da0306dfe91b4ee270244dfecf954da340bb)",
    "time(#ambient, SystemTime { tv_sec: 1608542592, tv_nsec: 0 })",
    "unique_revocation_id(0, hex:96123a8ee182336c4c63ad29f2b23549020da2a90841ac63ccec4c20413753b0)",
    "unique_revocation_id(1, hex:60e6f54cb7a20ee0859495abe176da0306dfe91b4ee270244dfecf954da340bb)",
}
  privileged rules: {}
  rules: {}
  checks: {
    "check if resource(#ambient, \"file1\")",
    "check if time(#ambient, $date), $date <= 2018-12-20T00:00:00+00:00",
}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 1, check_id: 1, rule: \"check if time(#ambient, $date), $date <= 2018-12-20T00:00:00+00:00\" })"])


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

validation:
verifier world:
World {
  facts: {
    "operation(#ambient, #read)",
    "owner(#ambient, #alice, \"file1\")",
    "resource(#ambient, \"file1\")",
    "revocation_id(0, hex:7b1c49cfd08df0bca951d50aa6f5062db8e4decce6713974186abd050382ab67)",
    "revocation_id(1, hex:c5fdfd4294c92dca9f14fa659c45c811828853bf913e71a5d18ef9eecd7a6cab)",
    "right(#authority, \"file1\", #read)",
    "right(#authority, \"file1\", #write)",
    "unique_revocation_id(0, hex:7b1c49cfd08df0bca951d50aa6f5062db8e4decce6713974186abd050382ab67)",
    "unique_revocation_id(1, hex:c5fdfd4294c92dca9f14fa659c45c811828853bf913e71a5d18ef9eecd7a6cab)",
}
  privileged rules: {
    "right(#authority, $1, #read) <- resource(#ambient, $1), owner(#ambient, $0, $1)",
    "right(#authority, $1, #write) <- resource(#ambient, $1), owner(#ambient, $0, $1)",
}
  rules: {}
  checks: {
    "check if resource(#ambient, $0), owner(#ambient, #alice, $0)",
    "check if right(#authority, $0, $1), resource(#ambient, $0), operation(#ambient, $1)",
}
  policies: {
    "allow if true",
}
}

Ok(0)


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

validation:
verifier world:
World {
  facts: {
    "operation(#ambient, #read)",
    "resource(#ambient, \"file2\")",
    "revocation_id(0, hex:f3db615323f48dc225b793ec494c30c1d4a800ec8299aa7558fe769803f1446b)",
    "right(#authority, \"file1\", #read)",
    "unique_revocation_id(0, hex:f3db615323f48dc225b793ec494c30c1d4a800ec8299aa7558fe769803f1446b)",
}
  privileged rules: {}
  rules: {}
  checks: {
    "check if right(#authority, $0, $1), resource(#ambient, $0), operation(#ambient, $1)",
}
  policies: {
    "allow if true",
}
}

Err(["Verifier(FailedVerifierCheck { check_id: 0, rule: \"check if right(#authority, $0, $1), resource(#ambient, $0), operation(#ambient, $1)\" })"])


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

validation for "file1":
verifier world:
World {
  facts: {
    "operation(#ambient, #read)",
    "resource(#ambient, \"file1\")",
    "revocation_id(0, hex:a6d33a7c61185cc962a4100d17176b72a60e95490af7c3cccbd244f3cce02b85)",
    "unique_revocation_id(0, hex:a6d33a7c61185cc962a4100d17176b72a60e95490af7c3cccbd244f3cce02b85)",
}
  privileged rules: {}
  rules: {}
  checks: {
    "check if resource(#ambient, \"file1\")",
}
  policies: {
    "allow if true",
}
}

Ok(0)
validation for "file2":
verifier world:
World {
  facts: {
    "operation(#ambient, #read)",
    "resource(#ambient, \"file2\")",
    "revocation_id(0, hex:a6d33a7c61185cc962a4100d17176b72a60e95490af7c3cccbd244f3cce02b85)",
    "unique_revocation_id(0, hex:a6d33a7c61185cc962a4100d17176b72a60e95490af7c3cccbd244f3cce02b85)",
}
  privileged rules: {}
  rules: {}
  checks: {
    "check if resource(#ambient, \"file1\")",
}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: \"check if resource(#ambient, \\\"file1\\\")\" })"])


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

validation for "file1":
verifier world:
World {
  facts: {
    "resource(#ambient, \"file1\")",
    "revocation_id(0, hex:d0e882a6d2405213cc7a8f2ac3f0041fecbf535177b6a6b4a581b48783a9d19b)",
    "revocation_id(1, hex:cab9e5395e49e41c53c3418796f73379a167d9c2d1504c99dac5e9bb06ec02cc)",
    "right(#authority, \"file1\", #read)",
    "right(#authority, \"file2\", #read)",
    "time(#ambient, SystemTime { tv_sec: 1608542592, tv_nsec: 0 })",
    "unique_revocation_id(0, hex:d0e882a6d2405213cc7a8f2ac3f0041fecbf535177b6a6b4a581b48783a9d19b)",
    "unique_revocation_id(1, hex:cab9e5395e49e41c53c3418796f73379a167d9c2d1504c99dac5e9bb06ec02cc)",
    "valid_date(\"file1\")",
}
  privileged rules: {}
  rules: {
    "valid_date(\"file1\") <- time(#ambient, $0), resource(#ambient, \"file1\"), $0 <= 2030-12-31T12:59:59+00:00",
    "valid_date($1) <- time(#ambient, $0), resource(#ambient, $1), $0 <= 1999-12-31T12:59:59+00:00, ![\"file1\"].contains($1)",
}
  checks: {
    "check if valid_date($0), resource(#ambient, $0)",
}
  policies: {
    "allow if true",
}
}

Ok(0)
validation for "file2":
verifier world:
World {
  facts: {
    "resource(#ambient, \"file2\")",
    "revocation_id(0, hex:d0e882a6d2405213cc7a8f2ac3f0041fecbf535177b6a6b4a581b48783a9d19b)",
    "revocation_id(1, hex:cab9e5395e49e41c53c3418796f73379a167d9c2d1504c99dac5e9bb06ec02cc)",
    "right(#authority, \"file1\", #read)",
    "right(#authority, \"file2\", #read)",
    "time(#ambient, SystemTime { tv_sec: 1608542592, tv_nsec: 0 })",
    "unique_revocation_id(0, hex:d0e882a6d2405213cc7a8f2ac3f0041fecbf535177b6a6b4a581b48783a9d19b)",
    "unique_revocation_id(1, hex:cab9e5395e49e41c53c3418796f73379a167d9c2d1504c99dac5e9bb06ec02cc)",
}
  privileged rules: {}
  rules: {
    "valid_date(\"file1\") <- time(#ambient, $0), resource(#ambient, \"file1\"), $0 <= 2030-12-31T12:59:59+00:00",
    "valid_date($1) <- time(#ambient, $0), resource(#ambient, $1), $0 <= 1999-12-31T12:59:59+00:00, ![\"file1\"].contains($1)",
}
  checks: {
    "check if valid_date($0), resource(#ambient, $0)",
}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: \"check if valid_date($0), resource(#ambient, $0)\" })"])


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

validation for "file1":
verifier world:
World {
  facts: {
    "resource(#ambient, \"file1\")",
    "revocation_id(0, hex:1da4cd4d7c60491948662acc237bb10599c6046e1ef09a867267b5e039a4d1b6)",
    "unique_revocation_id(0, hex:1da4cd4d7c60491948662acc237bb10599c6046e1ef09a867267b5e039a4d1b6)",
}
  privileged rules: {}
  rules: {}
  checks: {
    "check if resource(#ambient, $0), $0.matches(\"file[0-9]+.txt\")",
}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: \"check if resource(#ambient, $0), $0.matches(\\\"file[0-9]+.txt\\\")\" })"])
validation for "file123":
verifier world:
World {
  facts: {
    "resource(#ambient, \"file123.txt\")",
    "revocation_id(0, hex:1da4cd4d7c60491948662acc237bb10599c6046e1ef09a867267b5e039a4d1b6)",
    "unique_revocation_id(0, hex:1da4cd4d7c60491948662acc237bb10599c6046e1ef09a867267b5e039a4d1b6)",
}
  privileged rules: {}
  rules: {}
  checks: {
    "check if resource(#ambient, $0), $0.matches(\"file[0-9]+.txt\")",
}
  policies: {
    "allow if true",
}
}

Ok(0)


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

validation:
verifier world:
World {
  facts: {
    "must_be_present(#authority, \"hello\")",
    "revocation_id(0, hex:128099942c46fc6a4f9a8f8f0cc5d8b70c4d55d834255ef6065b62c967eef50c)",
    "unique_revocation_id(0, hex:128099942c46fc6a4f9a8f8f0cc5d8b70c4d55d834255ef6065b62c967eef50c)",
}
  privileged rules: {}
  rules: {}
  checks: {
    "check if must_be_present(#authority, $0) or must_be_present($0)",
}
  policies: {
    "allow if true",
}
}

Ok(0)


------------------------------

## check head name should be independent from fact names: test16_caveat_head_name.bc
biscuit:
```
Biscuit {
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
```

validation:
verifier world:
World {
  facts: {
    "check1(#test)",
    "revocation_id(0, hex:08321b952cecd6cc7ca5d3493ae391e44fcf3d3d55e63aa7e8b098217b7736c3)",
    "revocation_id(1, hex:e166c05f9ec0632fe286df76048a527a621d7ca08e2cd9f3995b4ee33b1e001c)",
    "unique_revocation_id(0, hex:08321b952cecd6cc7ca5d3493ae391e44fcf3d3d55e63aa7e8b098217b7736c3)",
    "unique_revocation_id(1, hex:e166c05f9ec0632fe286df76048a527a621d7ca08e2cd9f3995b4ee33b1e001c)",
}
  privileged rules: {}
  rules: {}
  checks: {
    "check if resource(#ambient, #hello)",
}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: \"check if resource(#ambient, #hello)\" })"])


------------------------------

## test expression syntax and all available operations: test17_expressions.bc
biscuit:
```
Biscuit {
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
```

validation:
verifier world:
World {
  facts: {
    "revocation_id(0, hex:09b4fab17d84885149e416bf10990d19b918a02854acd9ad96494994735cd25d)",
    "unique_revocation_id(0, hex:09b4fab17d84885149e416bf10990d19b918a02854acd9ad96494994735cd25d)",
}
  privileged rules: {}
  rules: {}
  checks: {
    "check if !false",
    "check if \"aaabde\".matches(\"a*c?.e\")",
    "check if \"abcD12\" == \"abcD12\"",
    "check if \"hello world\".starts_with(\"hello\") && \"hello world\".ends_with(\"world\")",
    "check if #abc == #abc",
    "check if 1 + 2 * 3 - 4 / 2 == 5",
    "check if 1 < 2",
    "check if 1 <= 1",
    "check if 1 <= 2",
    "check if 2 > 1",
    "check if 2 >= 1",
    "check if 2 >= 2",
    "check if 2019-12-04T09:46:41+00:00 < 2020-12-04T09:46:41+00:00",
    "check if 2019-12-04T09:46:41+00:00 <= 2020-12-04T09:46:41+00:00",
    "check if 2020-12-04T09:46:41+00:00 == 2020-12-04T09:46:41+00:00",
    "check if 2020-12-04T09:46:41+00:00 > 2019-12-04T09:46:41+00:00",
    "check if 2020-12-04T09:46:41+00:00 >= 2019-12-04T09:46:41+00:00",
    "check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00",
    "check if 3 == 3",
    "check if [\"abc\", \"def\"].contains(\"abc\")",
    "check if [#hello, #world].contains(#hello)",
    "check if [1, 2].contains(2)",
    "check if [2019-12-04T09:46:41+00:00, 2020-12-04T09:46:41+00:00].contains(2020-12-04T09:46:41+00:00)",
    "check if [false, true].contains(true)",
    "check if [hex:12ab, hex:34de].contains(hex:34de)",
    "check if false or true",
    "check if hex:12ab == hex:12ab",
    "check if true",
}
  policies: {
    "allow if true",
}
}

Ok(0)


------------------------------

## invalid block rule with unbound_variables: test18_unbound_variables_in_rule.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "check1", "test", "read", "unbound", "any1", "any2"]
    authority: Block[0] {
            symbols: ["check1", "test", "read"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if operation(#ambient, #read)
            ]
        }
    blocks: [
        Block[1] {
            symbols: ["unbound", "any1", "any2"]
            version: 1
            context: ""
            facts: []
            rules: [
                operation($unbound, #read) <- operation($any1, $any2)
            ]
            checks: []
        }
    ]
}
```

validation:
Err(["FailedLogic(InvalidBlockRule(0, \"operation($unbound, #read) <- operation($any1, $any2)\"))"])


------------------------------

## invalid block rule generating an #authority or #ambient symbol with a variable: test19_generating_ambient_from_variables.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "check1", "test", "read", "any"]
    authority: Block[0] {
            symbols: ["check1", "test", "read"]
            version: 1
            context: ""
            facts: []
            rules: []
            checks: [
                check if operation(#ambient, #read)
            ]
        }
    blocks: [
        Block[1] {
            symbols: ["any"]
            version: 1
            context: ""
            facts: []
            rules: [
                operation($ambient, #read) <- operation($ambient, $any)
            ]
            checks: []
        }
    ]
}
```

validation:
verifier world:
World {
  facts: {
    "operation(#ambient, #write)",
    "revocation_id(0, hex:cfbc25eee0ffc9bca3930e88469c45b8aa43e856464fc401db213c3d9587783a)",
    "revocation_id(1, hex:0e180a4400430a812b58751a3d3877af6ac2fe87559a32656c9ae78a4e973781)",
    "unique_revocation_id(0, hex:cfbc25eee0ffc9bca3930e88469c45b8aa43e856464fc401db213c3d9587783a)",
    "unique_revocation_id(1, hex:0e180a4400430a812b58751a3d3877af6ac2fe87559a32656c9ae78a4e973781)",
}
  privileged rules: {}
  rules: {
    "operation($ambient, #read) <- operation($ambient, $any)",
}
  checks: {
    "check if operation(#ambient, #read)",
}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: \"check if operation(#ambient, #read)\" })"])

