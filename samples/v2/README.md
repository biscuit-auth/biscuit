# Biscuit samples and expected results

root secret key: 12aca40167fbdd1a11037e9fd440e3d510d9d9dea70a6646aa4aaf84d718d75a
root public key: acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189

------------------------------

## basic token: test1_basic.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "check1", "0"]
    authority: Block {
            symbols: ["read", "write"]
            version: 2
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
        Block {
            symbols: ["check1", "0"]
            version: 2
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
    "revocation_id(0, hex:2d41aa8d0131f0a9f171ae849f99f78461157101001752852e1731281ad460b3)",
    "revocation_id(1, hex:601083ff09e19882d762976dbb9bc98851439052e8c1bf3da1f32718a5a57eed)",
    "right(#authority, \"file1\", #read)",
    "right(#authority, \"file1\", #write)",
    "right(#authority, \"file2\", #read)",
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
    authority: Block {
            symbols: ["read"]
            version: 2
            context: ""
            facts: [
                right(#authority, "file1", #read)
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block {
            symbols: ["check1", "0"]
            version: 2
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
    authority: Block {
            symbols: ["read", "write"]
            version: 2
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
        Block {
            symbols: ["check1", "0"]
            version: 2
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
    authority: Block {
            symbols: ["read", "write"]
            version: 2
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
        Block {
            symbols: ["check1", "0"]
            version: 2
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
    authority: Block {
            symbols: ["read", "write"]
            version: 2
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
        Block {
            symbols: ["check1", "0"]
            version: 2
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
    authority: Block {
            symbols: ["read", "write"]
            version: 2
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
        Block {
            symbols: ["check1", "0"]
            version: 2
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
    authority: Block {
            symbols: ["read", "write"]
            version: 2
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
        Block {
            symbols: ["check1", "0"]
            version: 2
            context: ""
            facts: []
            rules: []
            checks: [
                check if resource(#ambient, $0), operation(#ambient, #read), right(#authority, $0, #read)
            ]
        },
	Block {
            symbols: ["check2"]
            version: 2
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
    authority: Block {
            symbols: ["read"]
            version: 2
            context: ""
            facts: [
                right(#authority, "file1", #read)
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block {
            symbols: ["write", "check1", "0"]
            version: 2
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
    authority: Block {
            symbols: ["read"]
            version: 2
            context: ""
            facts: [
                right(#authority, "file1", #read)
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block {
            symbols: ["write", "check1", "0"]
            version: 2
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
    authority: Block {
            symbols: []
            version: 2
            context: ""
            facts: []
            rules: []
            checks: []
        }
    blocks: [
        Block {
            symbols: ["check1", "expiration", "date", "time"]
            version: 2
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
    "revocation_id(0, hex:97d9502fe0963f757c0f7e20e7d3a07b13f762c206c77506f4bd60af68565ce1)",
    "revocation_id(1, hex:5ccf80411f761b01c08783efede6b86898b920107507bd500c3854c8fe451f35)",
    "time(#ambient, SystemTime { tv_sec: 1608542592, tv_nsec: 0 })",
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
    authority: Block {
            symbols: ["1", "read", "owner", "0", "write"]
            version: 2
            context: ""
            facts: []
            rules: [
                right(#authority, $1, #read) <- resource(#ambient, $1), owner(#ambient, $0, $1),
                right(#authority, $1, #write) <- resource(#ambient, $1), owner(#ambient, $0, $1)
            ]
            checks: []
        }
    blocks: [
        Block {
            symbols: ["check1", "check2", "alice"]
            version: 2
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
    "revocation_id(0, hex:615c86ed96ffb3e756cee9a922facef14e7ceedd7833a22474ffa69986a02aab)",
    "revocation_id(1, hex:f5948d6b975b1f2e2571557588435445eeb088f6634c54247f0bc267bd11bc2a)",
    "right(#authority, \"file1\", #read)",
    "right(#authority, \"file1\", #write)",
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
    authority: Block {
            symbols: ["read"]
            version: 2
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
    "revocation_id(0, hex:74d206f233bdcadbb6a8bdca0303b0520d75f94944f0dfc1d3b8edb0b3200b53)",
    "right(#authority, \"file1\", #read)",
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
    authority: Block {
            symbols: ["check1"]
            version: 2
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
    "revocation_id(0, hex:6da467f30421f10f2bdd7eacb3ed3ce0741757c1afa8da1775f376dba88a5683)",
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
    "revocation_id(0, hex:6da467f30421f10f2bdd7eacb3ed3ce0741757c1afa8da1775f376dba88a5683)",
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
    authority: Block {
            symbols: ["read"]
            version: 2
            context: ""
            facts: [
                right(#authority, "file1", #read),
                right(#authority, "file2", #read)
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block {
            symbols: ["valid_date", "time", "0", "1", "check1"]
            version: 2
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
    "revocation_id(0, hex:9a30e5b4f22cdffd389bd06c77c8ef1912604b4ebe3f0de7ceea9f4ddb571da5)",
    "revocation_id(1, hex:35dc6e409f6582a669f0d41bf3cd9aa837a19764f0262e3dd8b6d2bdacee5b82)",
    "right(#authority, \"file1\", #read)",
    "right(#authority, \"file2\", #read)",
    "time(#ambient, SystemTime { tv_sec: 1608542592, tv_nsec: 0 })",
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
    "revocation_id(0, hex:9a30e5b4f22cdffd389bd06c77c8ef1912604b4ebe3f0de7ceea9f4ddb571da5)",
    "revocation_id(1, hex:35dc6e409f6582a669f0d41bf3cd9aa837a19764f0262e3dd8b6d2bdacee5b82)",
    "right(#authority, \"file1\", #read)",
    "right(#authority, \"file2\", #read)",
    "time(#ambient, SystemTime { tv_sec: 1608542592, tv_nsec: 0 })",
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
    authority: Block {
            symbols: ["resource_match", "0"]
            version: 2
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
    "revocation_id(0, hex:7d04d352cd30ad2875f003ff2ccc57dc7ec39763f3a823f87c9e26bf40b0310d)",
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
    "revocation_id(0, hex:7d04d352cd30ad2875f003ff2ccc57dc7ec39763f3a823f87c9e26bf40b0310d)",
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
    authority: Block {
            symbols: ["must_be_present"]
            version: 2
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
    "revocation_id(0, hex:a869933238d941c3c6fd2a6949844a35727741e04865faf66ebdeb0e2cadab40)",
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
    authority: Block {
            symbols: ["check1", "test", "hello"]
            version: 2
            context: ""
            facts: []
            rules: []
            checks: [
                check if resource(#ambient, #hello)
            ]
        }
    blocks: [
        Block {
            symbols: []
            version: 2
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
    "revocation_id(0, hex:4a366515e159a7577166d8158bdca3c0bb39cbabb4988824ad0c9aab5d3ea402)",
    "revocation_id(1, hex:2e8c19fefac5e54b7a8e21bb40eaf8aac70909e48f22c388ebb8cc742065d1dc)",
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
    authority: Block {
            symbols: ["query", "abc", "hello", "world"]
            version: 2
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
    "revocation_id(0, hex:fde35e855f6e4a1037e6698d3085bef54a71093dc06c2f2a2027e7c126a340d8)",
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
    authority: Block {
            symbols: ["check1", "test", "read"]
            version: 2
            context: ""
            facts: []
            rules: []
            checks: [
                check if operation(#ambient, #read)
            ]
        }
    blocks: [
        Block {
            symbols: ["unbound", "any1", "any2"]
            version: 2
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
    authority: Block {
            symbols: ["check1", "test", "read"]
            version: 2
            context: ""
            facts: []
            rules: []
            checks: [
                check if operation(#ambient, #read)
            ]
        }
    blocks: [
        Block {
            symbols: ["any"]
            version: 2
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
    "revocation_id(0, hex:345b72b425b0e134ba294e1183e91af519a154fefc8f3a6b788da47668fa90c9)",
    "revocation_id(1, hex:5262c65a6042072011eb868c9f47a279264324a2781d3dd38e72f3464dc93348)",
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

