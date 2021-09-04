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
                right("file1", #read),
                right("file2", #read),
                right("file1", #write)
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
                check if resource($0), operation(#read), right($0, #read)
            ]
        }
    ]
}
```

validation:
verifier world:
World {
  facts: {
    "resource(\"file1\")",
    "revocation_id(0, hex:d0b78d6ca60f7ecd2b73162cba6442b80cb88ae8ee2faff80ef2ef4a397b3ab1)",
    "revocation_id(1, hex:44245305d22048f923864a76f719a689a442f4ebc0e3f49922ecb77a1b181024)",
    "right(\"file1\", #read)",
    "right(\"file1\", #write)",
    "right(\"file2\", #read)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: \"check if resource($0), operation(#read), right($0, #read)\" })"])


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
                right("file1", #read)
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
                check if resource($0), operation(#read), right($0, #read)
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
                right("file1", #read),
                right("file2", #read),
                right("file1", #write)
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
                check if resource($0), operation(#read), right($0, #read)
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
                right("file1", #read),
                right("file2", #read),
                right("file1", #write)
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
                check if resource($0), operation(#read), right($0, #read)
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
                right("file1", #read),
                right("file2", #read),
                right("file1", #write)
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
                check if resource($0), operation(#read), right($0, #read)
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
                right("file1", #read),
                right("file2", #read),
                right("file1", #write)
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
                check if resource($0), operation(#read), right($0, #read)
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
                right("file1", #read),
                right("file2", #read),
                right("file1", #write)
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
                check if resource($0), operation(#read), right($0, #read)
            ]
        },
	Block {
            symbols: ["check2"]
            version: 2
            context: ""
            facts: []
            rules: []
            checks: [
                check if resource("file1")
            ]
        }
    ]
}
```

validation:
Err(["Format(Signature(InvalidSignature(\"signature error\")))"])


------------------------------

## scoped rules: test7_scoped_rules.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "user_id", "owner", "0", "read", "1", "check1"]
    authority: Block {
            symbols: ["user_id", "owner"]
            version: 2
            context: ""
            facts: [
                user_id("alice"),
                owner("alice", "file1")
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block {
            symbols: ["0", "read", "1", "check1"]
            version: 2
            context: ""
            facts: []
            rules: [
                right($0, #read) <- resource($0), user_id($1), owner($1, $0)
            ]
            checks: [
                check if resource($0), operation(#read), right($0, #read)
            ]
        }
    ]
}
```

biscuit3 (2 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "user_id", "owner", "0", "read", "1", "check1"]
    authority: Block {
            symbols: ["user_id", "owner"]
            version: 2
            context: ""
            facts: [
                user_id("alice"),
                owner("alice", "file1")
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block {
            symbols: ["0", "read", "1", "check1"]
            version: 2
            context: ""
            facts: []
            rules: [
                right($0, #read) <- resource($0), user_id($1), owner($1, $0)
            ]
            checks: [
                check if resource($0), operation(#read), right($0, #read)
            ]
        }
    ]
}
```

biscuit3 (2 checks):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "user_id", "owner", "0", "read", "1", "check1"]
    authority: Block {
            symbols: ["user_id", "owner"]
            version: 2
            context: ""
            facts: [
                user_id("alice"),
                owner("alice", "file1")
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block {
            symbols: ["0", "read", "1", "check1"]
            version: 2
            context: ""
            facts: []
            rules: [
                right($0, #read) <- resource($0), user_id($1), owner($1, $0)
            ]
            checks: [
                check if resource($0), operation(#read), right($0, #read)
            ]
        },
	Block {
            symbols: []
            version: 2
            context: ""
            facts: [
                owner("alice", "file2")
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
    "operation(#read)",
    "owner(\"alice\", \"file1\")",
    "owner(\"alice\", \"file2\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:85ac327fc6703282ec689d3d5cad2f62ba357bc5285012ee4210a6b8ac51dac6)",
    "revocation_id(1, hex:fa9013d9973657cd5050185a91f243859d982b6bd79a1fbf0c680e18ac526464)",
    "revocation_id(2, hex:d4c38cff9911dedd5ec9535ada28df22c25a7a6a2589ebb1bfc809a4e5dd2548)",
    "user_id(\"alice\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: \"check if resource($0), operation(#read), right($0, #read)\" })"])


------------------------------

## scoped checks: test8_scoped_checks.bc
biscuit2 (1 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "check1", "0"]
    authority: Block {
            symbols: ["read"]
            version: 2
            context: ""
            facts: [
                right("file1", #read)
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
                check if resource($0), operation(#read), right($0, #read)
            ]
        }
    ]
}
```

biscuit3 (2 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "check1", "0"]
    authority: Block {
            symbols: ["read"]
            version: 2
            context: ""
            facts: [
                right("file1", #read)
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
                check if resource($0), operation(#read), right($0, #read)
            ]
        }
    ]
}
```

biscuit3 (2 checks):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "check1", "0"]
    authority: Block {
            symbols: ["read"]
            version: 2
            context: ""
            facts: [
                right("file1", #read)
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
                check if resource($0), operation(#read), right($0, #read)
            ]
        },
	Block {
            symbols: []
            version: 2
            context: ""
            facts: [
                right("file2", #read)
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
    "operation(#read)",
    "resource(\"file2\")",
    "revocation_id(0, hex:d82a7c1a18cfa4314b375a87c0a56a3053da388ea98bff667ce4d5400b7aa981)",
    "revocation_id(1, hex:80992689d9e68ef103a9d620a107dc38fc020dd7e11238781547d6b8dfd7ad72)",
    "revocation_id(2, hex:f6624085e6ea881004795493f67e6335e109dd228a060d05083cc49c88233944)",
    "right(\"file1\", #read)",
    "right(\"file2\", #read)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: \"check if resource($0), operation(#read), right($0, #read)\" })"])


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
                check if resource("file1"),
                check if time($date), $date <= 2018-12-20T00:00:00+00:00
            ]
        }
    ]
}
```

validation:
verifier world:
World {
  facts: {
    "operation(#read)",
    "resource(\"file1\")",
    "revocation_id(0, hex:d30401ced69d2a2a3ce04bdee201316e7d256b2b44c25e2a2c3db54a226dfa0d)",
    "revocation_id(1, hex:53792abfe5845c74575528cc99803c02ab7dedf809f5b9ec5859a2f812c4627d)",
    "time(SystemTime { tv_sec: 1608542592, tv_nsec: 0 })",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 1, check_id: 1, rule: \"check if time($date), $date <= 2018-12-20T00:00:00+00:00\" })"])


------------------------------

## verifier scope: test10_verifier_scope.bc
biscuit3 (2 check):
```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read"]
    authority: Block {
            symbols: ["read"]
            version: 2
            context: ""
            facts: [
                right("file1", #read)
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block {
            symbols: []
            version: 2
            context: ""
            facts: [
                right("file2", #read)
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
    "operation(#read)",
    "resource(\"file2\")",
    "revocation_id(0, hex:81cec0693dbe65a0e6a97bec0e046629b96ade022bcbf0eb85a4f32fe08af176)",
    "revocation_id(1, hex:f478ed76b9c914b8626021362ea9a395fbd5ac5349ac11e200c76dec95271bce)",
    "right(\"file1\", #read)",
    "right(\"file2\", #read)",
}
  rules: {}
  checks: {
    "check if right($0, $1), resource($0), operation($1)",
}
  policies: {
    "allow if true",
}
}

Err(["Verifier(FailedVerifierCheck { check_id: 0, rule: \"check if right($0, $1), resource($0), operation($1)\" })"])


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
                right("file1", #read)
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
    "operation(#read)",
    "resource(\"file2\")",
    "revocation_id(0, hex:db94822670781ef0678edf5e9b11c5e75fcedb90c2243cd4993415a81b3abb23)",
    "right(\"file1\", #read)",
}
  rules: {}
  checks: {
    "check if right($0, $1), resource($0), operation($1)",
}
  policies: {
    "allow if true",
}
}

Err(["Verifier(FailedVerifierCheck { check_id: 0, rule: \"check if right($0, $1), resource($0), operation($1)\" })"])


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
                check if resource("file1")
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
    "operation(#read)",
    "resource(\"file1\")",
    "revocation_id(0, hex:3527bbda37830c73381efdeb2c41eac3468240ddb263e7897266cc391c21f37f)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}

Ok(0)
validation for "file2":
verifier world:
World {
  facts: {
    "operation(#read)",
    "resource(\"file2\")",
    "revocation_id(0, hex:3527bbda37830c73381efdeb2c41eac3468240ddb263e7897266cc391c21f37f)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: \"check if resource(\\\"file1\\\")\" })"])


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
                right("file1", #read),
                right("file2", #read)
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
                valid_date("file1") <- time($0), resource("file1"), $0 <= 2030-12-31T12:59:59+00:00,
                valid_date($1) <- time($0), resource($1), $0 <= 1999-12-31T12:59:59+00:00, !["file1"].contains($1)
            ]
            checks: [
                check if valid_date($0), resource($0)
            ]
        }
    ]
}
```

validation for "file1":
verifier world:
World {
  facts: {
    "resource(\"file1\")",
    "revocation_id(0, hex:3d5459878dfb4e1dba4e1ff1c585b98435117dd8f27b4402e836405e2073d58d)",
    "revocation_id(1, hex:6af4d647ce1df7e80c1cb4736087e21340fa3ed63b0d3f172d25e8e9964489c3)",
    "right(\"file1\", #read)",
    "right(\"file2\", #read)",
    "time(SystemTime { tv_sec: 1608542592, tv_nsec: 0 })",
    "valid_date(\"file1\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}

Ok(0)
validation for "file2":
verifier world:
World {
  facts: {
    "resource(\"file2\")",
    "revocation_id(0, hex:3d5459878dfb4e1dba4e1ff1c585b98435117dd8f27b4402e836405e2073d58d)",
    "revocation_id(1, hex:6af4d647ce1df7e80c1cb4736087e21340fa3ed63b0d3f172d25e8e9964489c3)",
    "right(\"file1\", #read)",
    "right(\"file2\", #read)",
    "time(SystemTime { tv_sec: 1608542592, tv_nsec: 0 })",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: \"check if valid_date($0), resource($0)\" })"])


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
                check if resource($0), $0.matches("file[0-9]+.txt")
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
    "resource(\"file1\")",
    "revocation_id(0, hex:c1e6da318f99f8ad00d1b6bbfcf56fbd7ffd2b499f5719e6a371ad82d1d94368)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: \"check if resource($0), $0.matches(\\\"file[0-9]+.txt\\\")\" })"])
validation for "file123":
verifier world:
World {
  facts: {
    "resource(\"file123.txt\")",
    "revocation_id(0, hex:c1e6da318f99f8ad00d1b6bbfcf56fbd7ffd2b499f5719e6a371ad82d1d94368)",
}
  rules: {}
  checks: {}
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
                must_be_present("hello")
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
    "must_be_present(\"hello\")",
    "revocation_id(0, hex:f1aba7009cd19fbc5605ad5a318775bc8bb4c887cc3d00f405689420a8ccdc6a)",
}
  rules: {}
  checks: {
    "check if must_be_present($0) or must_be_present($0)",
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
                check if resource(#hello)
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
    "revocation_id(0, hex:a4155e1642c441f169f8251cc3c1a1fa6b172543948c0a1a33d6409c28cae987)",
    "revocation_id(1, hex:63f977e2f45b998a920fba2bb69af6c02e4f094294dc89bdbaabb88f8a582186)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: \"check if resource(#hello)\" })"])


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
    "revocation_id(0, hex:388e71fd289d831f617872e9c454eac446a88080f34bfbe4da50fbce7144bcda)",
}
  rules: {}
  checks: {}
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
                check if operation(#read)
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
verifier world:
World {
  facts: {
    "operation(#write)",
    "revocation_id(0, hex:2e13a1deb4edc2c841324ab4120351aa8696d455750045511cb94ee243b9c35f)",
    "revocation_id(1, hex:628bf94715ce5ca37fe9d49bacee6a13fb77d8fd481b09875757bd567c93f0ca)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}

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
                check if operation(#read)
            ]
        }
    blocks: [
        Block {
            symbols: ["any"]
            version: 2
            context: ""
            facts: []
            rules: [
                operation(#read) <- operation($any)
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
    "operation(#read)",
    "operation(#write)",
    "revocation_id(0, hex:e0728acdc6aac007be70c2795e681c911fbf1bb0d8063a04258813d3cc36ebd2)",
    "revocation_id(1, hex:29226d29e16815d2adae6139b5761515f5fc219dcafbf1e113f03ab1b7134790)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}

Err(["Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: \"check if operation(#read)\" })"])

