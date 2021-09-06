# Biscuit samples and expected results

root secret key: 12aca40167fbdd1a11037e9fd440e3d510d9d9dea70a6646aa4aaf84d718d75a
root public key: acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189

------------------------------

## basic token: test1_basic.bc
### token

authority:
symbols: ["file1", "read", "file2", "write"]

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

```

### validation

verifier code:
```
resource("file1");
```

verifier world:
```
World {
  facts: {
    "resource(\"file1\")",
    "revocation_id(0, hex:0f96d9dfe80a884387e92c69eb7c0e8bccf3320117ebfe9841553885e19285f6)",
    "revocation_id(1, hex:30bfe7d51efafa81e488744e3c2849b0ac46f229fba172093c5ff2b80eaa1044)",
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

result: `Err(["Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: \"check if resource($0), operation(\\\"read\\\"), right($0, \\\"read\\\")\" })"])`


------------------------------

## different root key: test2_different_root_key.bc
### token

authority:
symbols: ["file1", "read"]

```
right("file1", "read");
```

1:
symbols: ["check1", "0"]

```
check if resource($0), operation("read"), right($0, "read");
```

```

### validation

result: `Err(["Format(Signature(InvalidSignature(\"signature error\")))"])`


------------------------------

## invalid signature format: test3_invalid_signature_format.bc
### token

authority:
symbols: ["file1", "read", "file2", "write"]

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

```

### validation

result: `Err(["Format(InvalidSignatureSize(16))"])`


------------------------------

## random block: test4_random_block.bc
### token

authority:
symbols: ["file1", "read", "file2", "write"]

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

```

### validation

result: `Err(["Format(Signature(InvalidSignature(\"signature error\")))"])`


------------------------------

## invalid signature: test5_invalid_signature.bc
### token

authority:
symbols: ["file1", "read", "file2", "write"]

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

```

### validation

result: `Err(["Format(Signature(InvalidSignature(\"signature error\")))"])`


------------------------------

## reordered blocks: test6_reordered_blocks.bc
### token

authority:
symbols: ["file1", "read", "file2", "write"]

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

```

### validation

result: `Err(["Format(Signature(InvalidSignature(\"signature error\")))"])`


------------------------------

## scoped rules: test7_scoped_rules.bc
### token

authority:
symbols: ["user_id", "alice", "owner", "file1"]

```
user_id("alice");
owner("alice", "file1");
```

1:
symbols: ["0", "read", "1", "check1"]

```
right($0, "read") <- resource($0), user_id($1), owner($1, $0);
check if resource($0), operation("read"), right($0, "read");
```

2:
symbols: ["file2"]

```
owner("alice", "file2");
```

```

### validation

verifier code:
```
resource("file2");
operation("read");
```

verifier world:
```
World {
  facts: {
    "operation(\"read\")",
    "owner(\"alice\", \"file1\")",
    "owner(\"alice\", \"file2\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:e02f6b03e6c135aabf0dec9d6652d555bb077e644cca809e2e9a3078ab6ffe73)",
    "revocation_id(1, hex:1e17451cbd10f072874cb2f71ec3e8070f05bf9547b32542a30a4f16f31aed45)",
    "revocation_id(2, hex:32bcb814710b1f6083e9574e5a11e6fc65b9d92b032f4827f6e50c2d58d2a519)",
    "user_id(\"alice\")",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(["Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: \"check if resource($0), operation(\\\"read\\\"), right($0, \\\"read\\\")\" })"])`


------------------------------

## scoped checks: test8_scoped_checks.bc
### token

authority:
symbols: ["file1", "read"]

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

```

### validation

verifier code:
```
resource("file2");
operation("read");
```

verifier world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:d11cee82bbf1491bcc7edab465258acc53c31d6575508335f67e8285e62d537c)",
    "revocation_id(1, hex:b43a8c3b0334be31eb308a27332fd47669efe2f3e858cfc8c02f8f91019c41d6)",
    "revocation_id(2, hex:86c20810f1439f9c6a616e426f903aecaa3dc0b009a9fd07b15feb0682ea8ba3)",
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

result: `Err(["Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: \"check if resource($0), operation(\\\"read\\\"), right($0, \\\"read\\\")\" })"])`


------------------------------

## expired token: test9_expired_token.bc
### token

authority:
symbols: []

```
```

1:
symbols: ["check1", "file1", "expiration", "date", "time"]

```
check if resource("file1");
check if time($date), $date <= 2018-12-20T00:00:00+00:00;
```

```

### validation

verifier code:
```
resource("file1");
operation("read");
time(2020-12-21T09:23:12+00:00);
```

verifier world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file1\")",
    "revocation_id(0, hex:d30401ced69d2a2a3ce04bdee201316e7d256b2b44c25e2a2c3db54a226dfa0d)",
    "revocation_id(1, hex:0f17932fdb2d90c01449b05b30ef11f79e133bbc5baf72b767ee6a53e2a9cba5)",
    "time(2020-12-21T09:23:12+00:00)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(["Block(FailedBlockCheck { block_id: 1, check_id: 1, rule: \"check if time($date), $date <= 2018-12-20T00:00:00+00:00\" })"])`


------------------------------

## verifier scope: test10_verifier_scope.bc
### token

authority:
symbols: ["file1", "read"]

```
right("file1", "read");
```

1:
symbols: ["file2"]

```
right("file2", "read");
```

```

### validation

verifier code:
```
resource("file2");
operation("read");

check if right($0, $1), resource($0), operation($1);
```

verifier world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:0a3610021893291c9cb313fe0dbf905fb69c8ea13b10baa417fca38bad1c2b36)",
    "revocation_id(1, hex:08138b73dc1409e86a7f12934e4fda2fa143f5323cf63711ecb996a3fd322f63)",
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

result: `Err(["Verifier(FailedVerifierCheck { check_id: 0, rule: \"check if right($0, $1), resource($0), operation($1)\" })"])`


------------------------------

## verifier authority checks: test11_verifier_authority_caveats.bc
### token

authority:
symbols: ["file1", "read"]

```
right("file1", "read");
```

```

### validation

verifier code:
```
resource("file2");
operation("read");

check if right($0, $1), resource($0), operation($1);
```

verifier world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:52810f896ce039bbcb954c293f2359ed0d4eab36a8f2bd5e37f5cf7c43a4b9e4)",
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

result: `Err(["Verifier(FailedVerifierCheck { check_id: 0, rule: \"check if right($0, $1), resource($0), operation($1)\" })"])`


------------------------------

## authority checks: test12_authority_caveats.bc
### token

authority:
symbols: ["check1", "file1"]

```
check if resource("file1");
```

```

### validation for "file1"

verifier code:
```
resource("file1");
operation("read");
```

verifier world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file1\")",
    "revocation_id(0, hex:72c2881a912c8e117605600c2d1dac170422e51a82af1c41d02e980bc8b27ca9)",
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

verifier code:
```
resource("file2");
operation("read");
```

verifier world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:72c2881a912c8e117605600c2d1dac170422e51a82af1c41d02e980bc8b27ca9)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(["Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: \"check if resource(\\\"file1\\\")\" })"])`


------------------------------

## block rules: test13_block_rules.bc
### token

authority:
symbols: ["file1", "read", "file2"]

```
right("file1", "read");
right("file2", "read");
```

1:
symbols: ["valid_date", "time", "0", "1", "check1"]

```
valid_date("file1") <- time($0), resource("file1"), $0 <= 2030-12-31T12:59:59+00:00;
valid_date($1) <- time($0), resource($1), $0 <= 1999-12-31T12:59:59+00:00, !["file1"].contains($1);
check if valid_date($0), resource($0);
```

```

### validation for "file1"

verifier code:
```
resource("file1");
time(2020-12-21T09:23:12+00:00);
```

verifier world:
```
World {
  facts: {
    "resource(\"file1\")",
    "revocation_id(0, hex:2840e519de1696684a69e511a2a802e5e6eaff7a78d94e908e8c94609ab8783b)",
    "revocation_id(1, hex:2b68ec0ff65537e6212d167d2ad7b0ee04cddd0ab6f9598ef3b0b080f9d271d0)",
    "right(\"file1\", \"read\")",
    "right(\"file2\", \"read\")",
    "time(2020-12-21T09:23:12+00:00)",
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

verifier code:
```
resource("file2");
time(2020-12-21T09:23:12+00:00);
```

verifier world:
```
World {
  facts: {
    "resource(\"file2\")",
    "revocation_id(0, hex:2840e519de1696684a69e511a2a802e5e6eaff7a78d94e908e8c94609ab8783b)",
    "revocation_id(1, hex:2b68ec0ff65537e6212d167d2ad7b0ee04cddd0ab6f9598ef3b0b080f9d271d0)",
    "right(\"file1\", \"read\")",
    "right(\"file2\", \"read\")",
    "time(2020-12-21T09:23:12+00:00)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(["Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: \"check if valid_date($0), resource($0)\" })"])`


------------------------------

## regex_constraint: test14_regex_constraint.bc
### token

authority:
symbols: ["resource_match", "0", "file[0-9]+.txt"]

```
check if resource($0), $0.matches("file[0-9]+.txt");
```

```

### validation for "file1"

verifier code:
```
resource("file1");
```

verifier world:
```
World {
  facts: {
    "resource(\"file1\")",
    "revocation_id(0, hex:80f05f2831e0fa1667ce5c5ff8753161e384ca3732d71d77eeb856b9953e5b59)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(["Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: \"check if resource($0), $0.matches(\\\"file[0-9]+.txt\\\")\" })"])`
### validation for "file123"

verifier code:
```
resource("file123.txt");
```

verifier world:
```
World {
  facts: {
    "resource(\"file123.txt\")",
    "revocation_id(0, hex:80f05f2831e0fa1667ce5c5ff8753161e384ca3732d71d77eeb856b9953e5b59)",
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

```

### validation

verifier code:
```

check if must_be_present($0) or must_be_present($0);
```

verifier world:
```
World {
  facts: {
    "must_be_present(\"hello\")",
    "revocation_id(0, hex:dcc8b221fb90ab87828b8d27e62810bce9046486dda01c763786d179a2a13a5c)",
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

```

### validation

verifier code:
```
```

verifier world:
```
World {
  facts: {
    "check1(\"test\")",
    "revocation_id(0, hex:1ffe0f15ba4ee93fb4d35431e5d83a1856beae6ab2ed5d20cfb1a57abf43b513)",
    "revocation_id(1, hex:0016c3ce871c58c03f952a108a8712daac2d98a7975cecb4adb148bb6a234f5f)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(["Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: \"check if resource(\\\"hello\\\")\" })"])`


------------------------------

## test expression syntax and all available operations: test17_expressions.bc
### token

authority:
symbols: ["query", "hello world", "hello", "world", "aaabde", "a*c?.e", "abcD12", "abc", "def"]

```
check if true;
check if !false;
check if false or true;
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
check if "abcD12" == "abcD12";
check if 2019-12-04T09:46:41+00:00 < 2020-12-04T09:46:41+00:00;
check if 2020-12-04T09:46:41+00:00 > 2019-12-04T09:46:41+00:00;
check if 2019-12-04T09:46:41+00:00 <= 2020-12-04T09:46:41+00:00;
check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00;
check if 2020-12-04T09:46:41+00:00 >= 2019-12-04T09:46:41+00:00;
check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00;
check if 2020-12-04T09:46:41+00:00 == 2020-12-04T09:46:41+00:00;
check if hex:12ab == hex:12ab;
check if [1, 2].contains(2);
check if [2019-12-04T09:46:41+00:00, 2020-12-04T09:46:41+00:00].contains(2020-12-04T09:46:41+00:00);
check if [false, true].contains(true);
check if ["abc", "def"].contains("abc");
check if [hex:12ab, hex:34de].contains(hex:34de);
```

```

### validation

verifier code:
```
```

verifier world:
```
World {
  facts: {
    "revocation_id(0, hex:ab737266e9316885ebc9c61df6e5b56e2691b366a0f2107e78bc2cc54683b22a)",
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

## invalid block rule with unbound_variables: test18_unbound_variables_in_rule.bc
### token

authority:
symbols: ["check1", "test", "read"]

```
check if operation("read");
```

1:
symbols: ["unbound", "any1", "any2"]

```
operation($unbound, "read") <- operation($any1, $any2);
```

```

### validation

verifier code:
```
operation("write");
```

verifier world:
```
World {
  facts: {
    "operation(\"write\")",
    "revocation_id(0, hex:9f766630542046f7e6b738a4ce5953f187b9ea891df45cd69656a74ba7501108)",
    "revocation_id(1, hex:f6fa94603e423ed4b78a0a82c77a4a79191712c56fb4b89a11f0a47b52febff8)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(["FailedLogic(InvalidBlockRule(0, \"operation($unbound, \\\"read\\\") <- operation($any1, $any2)\"))"])`


------------------------------

## invalid block rule generating an #authority or #ambient symbol with a variable: test19_generating_ambient_from_variables.bc
### token

authority:
symbols: ["check1", "test", "read"]

```
check if operation("read");
```

1:
symbols: ["any"]

```
operation("read") <- operation($any);
```

```

### validation

verifier code:
```
operation("write");
```

verifier world:
```
World {
  facts: {
    "operation(\"read\")",
    "operation(\"write\")",
    "revocation_id(0, hex:bc877aadd403a6c4f97525a3a4488a47122883edb9d2e4f0e8084be8b311b6f2)",
    "revocation_id(1, hex:13f15a0a93e6584858722b2d5b7785030cf3a2a6805a4d5af31e813b976de2c3)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(["Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: \"check if operation(\\\"read\\\")\" })"])`

