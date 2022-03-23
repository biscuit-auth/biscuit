# Biscuit samples and expected results

root secret key: 12aca40167fbdd1a11037e9fd440e3d510d9d9dea70a6646aa4aaf84d718d75a
root public key: acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189

------------------------------

## basic token: test1_basic.bc
### token

authority:
symbols: ["file1", "file2"]

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["check1", "0"]

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

authorizer code:
```
resource("file1");
```

revocation ids:
- `3ee1c0f42ba69ec63b1f39a6b3c57d25a4ccec452233ca6d40530ecfe83af4918fa78d9346f8b7c498545b54663960342b9ed298b2c8bbe2085b80c237b56f09`
- `12ae3232773614db9bbbdb62ebd07c369c822f1a31fd7ddfc60bc0cc0985839d15223d19847a746e737de65b9e2574d873362a7c1b69127cf5b69f0f6f10dc04`

authorizer world:
```
World {
  facts: {
    "resource(\"file1\")",
    "right(\"file1\", \"read\")",
    "right(\"file1\", \"write\")",
    "right(\"file2\", \"read\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if resource($0), operation(\"read\"), right($0, \"read\")" })] }))`


------------------------------

## different root key: test2_different_root_key.bc
### token

authority:
symbols: ["file1"]

```
right("file1", "read");
```

1:
symbols: ["check1", "0"]

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

result: `Err(Format(Signature(InvalidSignature("signature error: Verification equation was not satisfied"))))`


------------------------------

## invalid signature format: test3_invalid_signature_format.bc
### token

authority:
symbols: ["file1", "file2"]

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["check1", "0"]

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

result: `Err(Format(InvalidSignatureSize(16)))`


------------------------------

## random block: test4_random_block.bc
### token

authority:
symbols: ["file1", "file2"]

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["check1", "0"]

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

result: `Err(Format(Signature(InvalidSignature("signature error: Verification equation was not satisfied"))))`


------------------------------

## invalid signature: test5_invalid_signature.bc
### token

authority:
symbols: ["file1", "file2"]

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["check1", "0"]

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

result: `Err(Format(Signature(InvalidSignature("signature error: Verification equation was not satisfied"))))`


------------------------------

## reordered blocks: test6_reordered_blocks.bc
### token

authority:
symbols: ["file1", "file2"]

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["check1", "0"]

```
check if resource($0), operation("read"), right($0, "read");
```

2:
symbols: ["check2"]

```
check if resource("file1");
```

### validation

result: `Err(Format(Signature(InvalidSignature("signature error: Verification equation was not satisfied"))))`


------------------------------

## scoped rules: test7_scoped_rules.bc
### token

authority:
symbols: ["user_id", "alice", "file1"]

```
user_id("alice");
owner("alice", "file1");
```

1:
symbols: ["0", "1", "check1"]

```
right($0, "read") <- resource($0), user_id($1), owner($1, $0);
check if resource($0), operation("read"), right($0, "read");
```

2:
symbols: ["file2"]

```
owner("alice", "file2");
```

### validation

authorizer code:
```
resource("file2");
operation("read");
```

revocation ids:
- `02d287b0e5b22780192f8351538583c17f7d0200e064b32a1fcf07899e64ffb10e4de324f5c5ebc72c89a63e424317226cf555eb42dae81b2fd4639cf7591108`
- `0037d613778198f715d51300ee9a7e997e1608428aa921fa93f6689e2aa96b1843b81a0c1b0966a6e3a8cef3b7c24620364c965bfab7f04b782b195dfa648606`
- `95a0a288af1a34b28090aa910ff0ac6e3caee45476fabb4748a3fa596d17f5164a360609a3cc8badb3d4b262ae5ac4f05f23dfcdef4c773b7cadb82d274c3408`

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "owner(\"alice\", \"file1\")",
    "owner(\"alice\", \"file2\")",
    "resource(\"file2\")",
    "user_id(\"alice\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if resource($0), operation(\"read\"), right($0, \"read\")" })] }))`


------------------------------

## scoped checks: test8_scoped_checks.bc
### token

authority:
symbols: ["file1"]

```
right("file1", "read");
```

1:
symbols: ["check1", "0"]

```
check if resource($0), operation("read"), right($0, "read");
```

2:
symbols: ["file2"]

```
right("file2", "read");
```

### validation

authorizer code:
```
resource("file2");
operation("read");
```

revocation ids:
- `567682495bf002eb84c46491e40fad8c55943d918c65e2c110b1b88511bf393072c0305a243e3d632ca5f1e9b0ace3e3582de84838c3a258480657087c267f02`
- `a6ff5553b573a28717ceba206f9afb6c4052879303e6566183736f66c4f381db219adb630fd61b340e5a843c4bd9e0a66c802a46c2aaeb364c239b396c11040d`
- `6ddd3bb88b98c0624f5b6b85dd35d0227b2c4085cd8ea67ebb3d2cec92f0c501cae4cdae766aa6d03667ab4553cd9d003f1ddb54cecf183a09aa6bb68c7b8002`

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "right(\"file1\", \"read\")",
    "right(\"file2\", \"read\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if resource($0), operation(\"read\"), right($0, \"read\")" })] }))`


------------------------------

## expired token: test9_expired_token.bc
### token

authority:
symbols: []

```
```

1:
symbols: ["check1", "file1", "expiration", "date"]

```
check if resource("file1");
check if time($date), $date <= 2018-12-20T00:00:00Z;
```

### validation

authorizer code:
```
resource("file1");
operation("read");
time(2020-12-21T09:23:12Z);
```

revocation ids:
- `b2474f3e0a5788cdeff811f2599497a04d1ad71ca48dbafb90f20a950d565dda0b86bd6c9072a727c19b6b20a1ae10d8cb88155186550b77016ffd1dca9a6203`
- `acbf0c948ba0271866ecc15a04fa3effa9485c543d70e1d5e4ce0a5d70d91c208d7d526151a2ad01a93caf46df2ecfb92fdedab03586ca895a12d869c8ad350e`

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file1\")",
    "time(2020-12-21T09:23:12Z)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 1, rule: "check if time($date), $date <= 2018-12-20T00:00:00Z" })] }))`


------------------------------

## authorizer scope: test10_authorizer_scope.bc
### token

authority:
symbols: ["file1"]

```
right("file1", "read");
```

1:
symbols: ["file2"]

```
right("file2", "read");
```

### validation

authorizer code:
```
resource("file2");
operation("read");

check if right($0, $1), resource($0), operation($1);
```

revocation ids:
- `b9ecf192ecb1bbb10e45320c1c86661f0c6b6bd28e89fdd8fa838fe0ab3f754229f7fbbf92ad978d36f744c345c69bc156a2a91a2979a3c235a9d936d401b404`
- `839728735701e589c2612e655afa2b53f573480e6a0477ae68ed71587987d1af398a31296bdec0b6eccee9348f4b4c23ca1031e809991626c579fef80b1d380d`

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "right(\"file1\", \"read\")",
    "right(\"file2\", \"read\")",
}
  rules: {}
  checks: {
    "check if right($0, $1), resource($0), operation($1)",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Authorizer(FailedAuthorizerCheck { check_id: 0, rule: "check if right($0, $1), resource($0), operation($1)" })] }))`


------------------------------

## authorizer authority checks: test11_authorizer_authority_caveats.bc
### token

authority:
symbols: ["file1"]

```
right("file1", "read");
```

### validation

authorizer code:
```
resource("file2");
operation("read");

check if right($0, $1), resource($0), operation($1);
```

revocation ids:
- `593d273d141bf23a3e89b55fffe1b3f96f683a022bb763e78f4e49f31a7cf47668c3fd5e0f580727ac9113ede302d34264597f6f1e6c6dd4167836d57aedf504`

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "right(\"file1\", \"read\")",
}
  rules: {}
  checks: {
    "check if right($0, $1), resource($0), operation($1)",
}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Authorizer(FailedAuthorizerCheck { check_id: 0, rule: "check if right($0, $1), resource($0), operation($1)" })] }))`


------------------------------

## authority checks: test12_authority_caveats.bc
### token

authority:
symbols: ["check1", "file1"]

```
check if resource("file1");
```

### validation for "file1"

authorizer code:
```
resource("file1");
operation("read");
```

revocation ids:
- `548609f44a483e7d41f647bec72056c9d8bba25a52b613a31560f147bf3674224d4814174ee5081c4b21e9020887284a9c316757b4c328447f9d585c249aeb08`

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file1\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`
### validation for "file2"

authorizer code:
```
resource("file2");
operation("read");
```

revocation ids:
- `548609f44a483e7d41f647bec72056c9d8bba25a52b613a31560f147bf3674224d4814174ee5081c4b21e9020887284a9c316757b4c328447f9d585c249aeb08`

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if resource(\"file1\")" })] }))`


------------------------------

## block rules: test13_block_rules.bc
### token

authority:
symbols: ["file1", "file2"]

```
right("file1", "read");
right("file2", "read");
```

1:
symbols: ["valid_date", "0", "1", "check1"]

```
valid_date("file1") <- time($0), resource("file1"), $0 <= 2030-12-31T12:59:59Z;
valid_date($1) <- time($0), resource($1), $0 <= 1999-12-31T12:59:59Z, !["file1"].contains($1);
check if valid_date($0), resource($0);
```

### validation for "file1"

authorizer code:
```
resource("file1");
time(2020-12-21T09:23:12Z);
```

revocation ids:
- `d251352efd4e4c72e8a1609fce002f558f1a0bb5e36cd3d8b3a6c6599e3960880f21bea6fe1857f4ecbc2c399dd77829b154e75f1323e9dec413aad70f97650d`
- `b5c6b0423d971306ba360347b9f0b04d49b8bc07a9e577346df6839ceac418c75197b65fbb648cbc9b9296e15e601ba143b1c59b7329e66a569f0f141b09750e`

authorizer world:
```
World {
  facts: {
    "resource(\"file1\")",
    "right(\"file1\", \"read\")",
    "right(\"file2\", \"read\")",
    "time(2020-12-21T09:23:12Z)",
    "valid_date(\"file1\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`
### validation for "file2"

authorizer code:
```
resource("file2");
time(2020-12-21T09:23:12Z);
```

revocation ids:
- `d251352efd4e4c72e8a1609fce002f558f1a0bb5e36cd3d8b3a6c6599e3960880f21bea6fe1857f4ecbc2c399dd77829b154e75f1323e9dec413aad70f97650d`
- `b5c6b0423d971306ba360347b9f0b04d49b8bc07a9e577346df6839ceac418c75197b65fbb648cbc9b9296e15e601ba143b1c59b7329e66a569f0f141b09750e`

authorizer world:
```
World {
  facts: {
    "resource(\"file2\")",
    "right(\"file1\", \"read\")",
    "right(\"file2\", \"read\")",
    "time(2020-12-21T09:23:12Z)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if valid_date($0), resource($0)" })] }))`


------------------------------

## regex_constraint: test14_regex_constraint.bc
### token

authority:
symbols: ["resource_match", "0", "file[0-9]+.txt"]

```
check if resource($0), $0.matches("file[0-9]+.txt");
```

### validation for "file1"

authorizer code:
```
resource("file1");
```

revocation ids:
- `4bb969d5cf558d831892f3ef52115a217fb059968eb1d109958076cd3521cd88ddd161f864bf3335e5534a504947d6c4f684bd62a37ba2b23fa30260a825bf04`

authorizer world:
```
World {
  facts: {
    "resource(\"file1\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if resource($0), $0.matches(\"file[0-9]+.txt\")" })] }))`
### validation for "file123"

authorizer code:
```
resource("file123.txt");
```

revocation ids:
- `4bb969d5cf558d831892f3ef52115a217fb059968eb1d109958076cd3521cd88ddd161f864bf3335e5534a504947d6c4f684bd62a37ba2b23fa30260a825bf04`

authorizer world:
```
World {
  facts: {
    "resource(\"file123.txt\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`


------------------------------

## multi queries checks: test15_multi_queries_caveats.bc
### token

authority:
symbols: ["must_be_present", "hello"]

```
must_be_present("hello");
```

### validation

authorizer code:
```

check if must_be_present($0) or must_be_present($0);
```

revocation ids:
- `d3eee8a74eacec9c51d4d1eb29b479727dfaafa9df7d4c651d07c493c56f3a5f037a51139ebd036f50d1159d12bccec3e377bbd32db90a39dd52c4776757ad0b`

authorizer world:
```
World {
  facts: {
    "must_be_present(\"hello\")",
}
  rules: {}
  checks: {
    "check if must_be_present($0) or must_be_present($0)",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`


------------------------------

## check head name should be independent from fact names: test16_caveat_head_name.bc
### token

authority:
symbols: ["check1", "test", "hello"]

```
check if resource("hello");
```

1:
symbols: []

```
check1("test");
```

### validation

authorizer code:
```
```

revocation ids:
- `c88d4b7afeac437596964e403a36ee113da1c20c4fec8a340fa97613ff585f520eb5fc0cbbd80dd6b6fa0127d03a1c773d7c5605197d5382e660dac3c957bb01`
- `3213d5bbef6e3bcfc09ab54d16e824d69a243a90f748c41f60c7a4a8a81bc47ce16f57a3d252b00143c7a554d926988fbbba5abdb2ef826c933cce8c2122710f`

authorizer world:
```
World {
  facts: {
    "check1(\"test\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if resource(\"hello\")" })] }))`


------------------------------

## test expression syntax and all available operations: test17_expressions.bc
### token

authority:
symbols: ["hello world", "hello", "world", "aaabde", "a*c?.e", "abd", "aaa", "b", "de", "abcD12", "abc", "def"]

```
check if true;
check if !false;
check if !false && true;
check if false or true;
check if (true || false) && true;
check if 1 < 2;
check if 2 > 1;
check if 1 <= 2;
check if 1 <= 1;
check if 2 >= 1;
check if 2 >= 2;
check if 3 == 3;
check if 1 + 2 * 3 - 4 / 2 == 5;
check if "hello world".starts_with("hello") && "hello world".ends_with("world");
check if "aaabde".matches("a*c?.e");
check if "aaabde".contains("abd");
check if "aaabde" == "aaa" + "b" + "de";
check if "abcD12" == "abcD12";
check if 2019-12-04T09:46:41Z < 2020-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z > 2019-12-04T09:46:41Z;
check if 2019-12-04T09:46:41Z <= 2020-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z >= 2020-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z >= 2019-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z >= 2020-12-04T09:46:41Z;
check if 2020-12-04T09:46:41Z == 2020-12-04T09:46:41Z;
check if hex:12ab == hex:12ab;
check if [1, 2].contains(2);
check if [2019-12-04T09:46:41Z, 2020-12-04T09:46:41Z].contains(2020-12-04T09:46:41Z);
check if [false, true].contains(true);
check if ["abc", "def"].contains("abc");
check if [hex:12ab, hex:34de].contains(hex:34de);
```

### validation

authorizer code:
```
```

revocation ids:
- `f1391d7549f4c165dd58878c8433bdc23634533f4910bcd37fc53d5b3b29c542ef1b46a38a42beb2df911d526a52f65774e1d60f910dbe15ca1591735617240b`

authorizer world:
```
World {
  facts: {}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`


------------------------------

## invalid block rule with unbound_variables: test18_unbound_variables_in_rule.bc
### token

authority:
symbols: ["check1", "test"]

```
check if operation("read");
```

1:
symbols: ["unbound", "any1", "any2"]

```
operation($unbound, "read") <- operation($any1, $any2);
```

### validation

authorizer code:
```
operation("write");
```

revocation ids:
- `bc12e3a0f15ba41b7f14dd9776d359f81d7a8372ec8e46ac5a211bc52f5ad7777c273a1925015a92f88e230a97d3b435ff060b8079bce6f28fc3530416be6f0f`
- `2385d7b5cbafc2ef556fc8f032fc7945a51ea724904e0ff06900764c86faac3a0cfb0b27f5a4275d59f037a3956090e40fb95e84b3cf71901d12c0994427dc0c`

authorizer world:
```
World {
  facts: {
    "operation(\"write\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(InvalidBlockRule(0, "operation($unbound, \"read\") <- operation($any1, $any2)")))`


------------------------------

## invalid block rule generating an #authority or #ambient symbol with a variable: test19_generating_ambient_from_variables.bc
### token

authority:
symbols: ["check1", "test"]

```
check if operation("read");
```

1:
symbols: ["any"]

```
operation("read") <- operation($any);
```

### validation

authorizer code:
```
operation("write");
```

revocation ids:
- `467ae49d69ccd51f8c47e371966b4db2bb615f66a19759c86b6f3d09d46430b5f4caac419bd5c9da8d93ffa349310ca8f99ad10f50bbd6c0a4039a65ccb59a0d`
- `8855d4ea222a90718665534e6437444623bc7edd5695e65b85d90ee229264654c05be45538582070fb88cfceb250fc59666b0e3b674e0839411d6fc5a6d17a0e`

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "operation(\"write\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if operation(\"read\")" })] }))`


------------------------------

## sealed token: test20_sealed.bc
### token

authority:
symbols: ["file1", "file2"]

```
right("file1", "read");
right("file2", "read");
right("file1", "write");
```

1:
symbols: ["check1", "0"]

```
check if resource($0), operation("read"), right($0, "read");
```

### validation

authorizer code:
```
resource("file1");
operation("read");
```

revocation ids:
- `b279f8c6fee5ea3c3fcb5109d8c6b35ba3fecea64d83a4dc387102b9401633a1558ac6ac50ddd7fd9e9877f936f9f4064abd467faeca2bef3114b9695eb0580e`
- `b3baf8fe8c41cedbc7b7d0abe3aa20535b1226693df8be2a46827d33f46d77b3a23898fda4ce44e05203cb35de54541225744ac49216d86faffd389188865504`

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file1\")",
    "right(\"file1\", \"read\")",
    "right(\"file1\", \"write\")",
    "right(\"file2\", \"read\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`


------------------------------

## parsing: test21_parsing.bc
### token

authority:
symbols: ["ns::fact_123", "hello é\t😁"]

```
ns::fact_123("hello é	😁");
```

### validation

authorizer code:
```

check if ns::fact_123("hello é	😁");
```

revocation ids:
- `4797a528328c8b5fb7939cc8956d8cda2513f552466eee501e26ea13a6cf6b4a381fd74ae547a9b50b627825142287d899b9d7bd1b5cfb18664a1be78320ea06`

authorizer world:
```
World {
  facts: {
    "ns::fact_123(\"hello é\t😁\")",
}
  rules: {}
  checks: {
    "check if ns::fact_123(\"hello é\t😁\")",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`


------------------------------

## default_symbols: test22_default_symbols.bc
### token

authority:
symbols: []

```
read(0);
write(1);
resource(2);
operation(3);
right(4);
time(5);
role(6);
owner(7);
tenant(8);
namespace(9);
user(10);
team(11);
service(12);
admin(13);
email(14);
group(15);
member(16);
ip_address(17);
client(18);
client_ip(19);
domain(20);
path(21);
version(22);
cluster(23);
node(24);
hostname(25);
nonce(26);
query(27);
```

### validation

authorizer code:
```

check if read(0), write(1), resource(2), operation(3), right(4), time(5), role(6), owner(7), tenant(8), namespace(9), user(10), team(11), service(12), admin(13), email(14), group(15), member(16), ip_address(17), client(18), client_ip(19), domain(20), path(21), version(22), cluster(23), node(24), hostname(25), nonce(26), query(27);
```

revocation ids:
- `38094260b324eff92db2ef79e715d88c18503c0dafa400bff900399f2ab0840cedc5ac25bdd3e97860b3f9e78ca5e0df67a113eb87be50265d49278efb13210f`

authorizer world:
```
World {
  facts: {
    "admin(13)",
    "client(18)",
    "client_ip(19)",
    "cluster(23)",
    "domain(20)",
    "email(14)",
    "group(15)",
    "hostname(25)",
    "ip_address(17)",
    "member(16)",
    "namespace(9)",
    "node(24)",
    "nonce(26)",
    "operation(3)",
    "owner(7)",
    "path(21)",
    "query(27)",
    "read(0)",
    "resource(2)",
    "right(4)",
    "role(6)",
    "service(12)",
    "team(11)",
    "tenant(8)",
    "time(5)",
    "user(10)",
    "version(22)",
    "write(1)",
}
  rules: {}
  checks: {
    "check if read(0), write(1), resource(2), operation(3), right(4), time(5), role(6), owner(7), tenant(8), namespace(9), user(10), team(11), service(12), admin(13), email(14), group(15), member(16), ip_address(17), client(18), client_ip(19), domain(20), path(21), version(22), cluster(23), node(24), hostname(25), nonce(26), query(27)",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`


------------------------------

## execution scope: test23_execution_scope.bc
### token

authority:
symbols: ["authority_fact"]

```
authority_fact(1);
```

1:
symbols: ["block1_fact"]

```
block1_fact(1);
```

2:
symbols: ["var"]

```
check if authority_fact($var);
check if block1_fact($var);
```

### validation

authorizer code:
```
```

revocation ids:
- `6a3606836bc63b858f96ce5000c9bead8eda139ab54679a2a8d7a9984c2e5d864b93280acc1b728bed0be42b5b1c3be10f48a13a4dbd05fd5763de5be3855108`
- `5f1468fc60999f22c4f87fa088a83961188b4e654686c5b04bdc977b9ff4666d51a3d8be5594f4cef08054d100f31d1637b50bb394de7cccafc643c9b650390b`
- `3eda05ddb65ee90d715cefc046837c01de944d8c4a7ff67e3d9a9d8470b5e214a20a8b9866bfe5e0d385e530b75ec8fcfde46b7dd6d4d6647d1e955c9d2fb90d`

authorizer world:
```
World {
  facts: {
    "authority_fact(1)",
    "block1_fact(1)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 2, check_id: 1, rule: "check if block1_fact($var)" })] }))`

