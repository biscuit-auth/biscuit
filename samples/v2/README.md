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

authorizer world:
```
World {
  facts: {
    "resource(\"file1\")",
    "revocation_id(0, hex:776ba45c736c502fb9af546b1757a04dfb7d13e2e22bee8ab87f2ec894e6f01eeb2757bdcd83874f0d1160fd16dfaee0a95c3dad640dd7f65e3ec231d31dcd02)",
    "revocation_id(1, hex:366f557a51b3d2fd8370f01bd099375f5395d08a52ee6a539b874fc439cf0eb80f2ce79ed31f5c5243aaa9ba2ec08dc4d5de7851ddf81e8785e24ab4ff09720b)",
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
symbols: ["user_id", "alice", "owner", "file1"]

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

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "owner(\"alice\", \"file1\")",
    "owner(\"alice\", \"file2\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:d2454c600567418982b2787c1fbc4e04d6f59f1576b6613d1cacd30440f673a0c44728457a39fb8085e4152a8195e0bdfbe3a5fdcfafd08b33ad53c3274c6d0c)",
    "revocation_id(1, hex:f97d7643129a295c4a634cc87b5cce94cdbfbebdc3b77a311b0fda097a93375c47e38d9f084738729d26ee87c54d443d7d5051cce50f7f8d470a9e1c5301e10e)",
    "revocation_id(2, hex:27d5e1eca67c509298a46a9bf980d3f02e936a4972b90f794a746436201aa1f48e34f32841570a3211d2b88304999e5781010d1c6e7f1d335fa9773a74f4e707)",
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

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:2a2172129529841b80440183bdd088f6756d34a8526519bd9d24a55a6101a0c1d9605fa15e6c2d973caf22d3c301f58615c78ac464b04c1bea8a281761742108)",
    "revocation_id(1, hex:71671cff60f4384436782998a498407db952ae4b9229047d3e925891254df64bebf26d8dfa611d0db26998c07140959b874a3ea45ce0204bd60708fea8924100)",
    "revocation_id(2, hex:1cd06aae69a90d9b9fca61a2a3d5f7bbc57f329f4fe5fa55550c5258b76c3394a6afd41bb3c44c50a40e3dc72cb58ee6dd4604e2a3ddeae257300d427a4aac0d)",
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

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file1\")",
    "revocation_id(0, hex:16d0a9d7f3d29ee2112d67451c8e4ff07bd5366a6cdb082cf4fcb66e6d15a57a22009ef1018fc4d0f9184edb0900df161807bc6f8287275f32eae6b5b1c57100)",
    "revocation_id(1, hex:24d6379a0248af1d13732e97731b7fd05335b1ccdd32aab84c3204ba5b10e63ca278817672197df40ec6904866b1f16560ac578403f66cd3d4382718a6f5a70c)",
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

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:2e84bc1153e8a893c3dd6a5f0ca3f0931f70c5a19215d388ec81fc8ccef711503c4ee50066c007bdc18fe958aa128c2975c9e5934f33372126f99da03833150e)",
    "revocation_id(1, hex:69442c29c7546b752f1cb0800c397800df00ef2828158f10a04fb56b66ea58413ea827e5c050d5d931c5f3f51361fc314c288bf9182bf7a72e38bdfda8e5af0b)",
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

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:c71f68430e917e4db2e9c935b5fc23f04ec7bad4ad690b566b7232f148aa2f5be18db42f10ca105e5f9a65b3102ab7beb00f5b7d3dcca72ee368520e4414e900)",
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

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file1\")",
    "revocation_id(0, hex:0d313cc11a09af8844290865c919220aebfb260aa5a1f738c8a8f3df677902e5ea06f408fa316d527926a688764a2c5e06cdecf14bc1ace3e6128323dcb8c801)",
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

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:0d313cc11a09af8844290865c919220aebfb260aa5a1f738c8a8f3df677902e5ea06f408fa316d527926a688764a2c5e06cdecf14bc1ace3e6128323dcb8c801)",
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

authorizer world:
```
World {
  facts: {
    "resource(\"file1\")",
    "revocation_id(0, hex:c5958dec7ca5ae3cc043794655ed50ded0da3abdb2cb304d19aec65247533e836df530cb5038ce095615f236300324b5e00c28e61bdedb18af6c3c37a87b3200)",
    "revocation_id(1, hex:13fe46046589e018f14cab7fe3aaad91cea7b4637d53f2dcdbec3f7305783c69b23ee18443f328db4b7f2e50b7b8d7822e48af735f11e7fbaa5de4c954712202)",
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

authorizer world:
```
World {
  facts: {
    "resource(\"file2\")",
    "revocation_id(0, hex:c5958dec7ca5ae3cc043794655ed50ded0da3abdb2cb304d19aec65247533e836df530cb5038ce095615f236300324b5e00c28e61bdedb18af6c3c37a87b3200)",
    "revocation_id(1, hex:13fe46046589e018f14cab7fe3aaad91cea7b4637d53f2dcdbec3f7305783c69b23ee18443f328db4b7f2e50b7b8d7822e48af735f11e7fbaa5de4c954712202)",
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

authorizer world:
```
World {
  facts: {
    "resource(\"file1\")",
    "revocation_id(0, hex:9752ecf19b270129471b459de5b8fbf6c04ad652d1ebd042f79efd8ceb6d14fd3a92ff5f2ada3996895bc4e9effe2b723b775d28ddcdc2365294a4420b67790f)",
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

authorizer world:
```
World {
  facts: {
    "resource(\"file123.txt\")",
    "revocation_id(0, hex:9752ecf19b270129471b459de5b8fbf6c04ad652d1ebd042f79efd8ceb6d14fd3a92ff5f2ada3996895bc4e9effe2b723b775d28ddcdc2365294a4420b67790f)",
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

authorizer world:
```
World {
  facts: {
    "must_be_present(\"hello\")",
    "revocation_id(0, hex:aa4293d9e62461c2871071a3c40c515427927fa47e7e123e857ba1f41275a87ca53db2183023d09a4ad09cf6c1e70c816a48ab0b532a49c3ebb903cfbc66cf01)",
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

authorizer world:
```
World {
  facts: {
    "check1(\"test\")",
    "revocation_id(0, hex:aa8f26e32b6a55fe99decfb0f2c229776cc30360e5b68a5b06e730f1e9a13697f87929592f37b7b58dd00dececd6fa40540a3879f74bd232505f1c419907000c)",
    "revocation_id(1, hex:02766fa2dbb0bd5a2d4d3fc4e0dd9252ec4dc118fe5bc0eafb67fbce0ddf6a86f4db7ecc0b1da14c210b8dcae53fcfc44565edb32ba18bfc9ca9f97258c4db0d)",
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

authorizer world:
```
World {
  facts: {
    "revocation_id(0, hex:39e2c7e2319cc614acf881d06bfd5e344a0e7ed2c4c15e0d068f66467276dead3db6d4aca2cf5b688fc84f13861c7c89c047adde161f962dee18099902da5608)",
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

authorizer world:
```
World {
  facts: {
    "operation(\"write\")",
    "revocation_id(0, hex:3556aa839ffa045eaf9b648fa8567d2b52595bec5e425380ea5cc5c39e20af01d0ac6f31d6f42cda53b5b0d244c7a36dd1c0aaa782f5bf75d2f7f9418e17ea06)",
    "revocation_id(1, hex:56207b912460b8d319c16541fb0bcd95282fa022c8591cf7898c36aed82b4bfe8449348e90dd32174790222a93c3c6fc65d57eac3b54f95300c6eae098d1b700)",
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

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "operation(\"write\")",
    "revocation_id(0, hex:98030c61bf4e130289d435faf5ee967911c603aac8d69332c5cf6e645ed5a85df73f97f4fd6268faaee0061be491e9274713eb8d59395e2c54ad025f70463302)",
    "revocation_id(1, hex:702f7b9e5b8bbde0fdd4169c9c9e2d098574f56b6583202dbef9bf572fec83d1074cb747e56c1263e7680ada4bfad60f4840e76d6fdb61b646cdde085bc9300f)",
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

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file1\")",
    "revocation_id(0, hex:3cfbf57a818e942fd59fef67c616b4f0b5df673f5ae2407fcbecb3e3ee9f90019db7da7cf933e87a7377477b07527061ef5231d749f414445d45bb3fe3fb4306)",
    "revocation_id(1, hex:5d58832964b3b6f605fb0818414e6ac0f8ffa778516321a111c6be42ea473a7913d558476bd1b6ec0cb47e7c0324ed0a9e826659f407f540de218efc8afd6704)",
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

authorizer world:
```
World {
  facts: {
    "ns::fact_123(\"hello é\t😁\")",
    "revocation_id(0, hex:adf27d92fc268727450a1d03c7cdf1fb14ddd0157a105bd68a14df9aecce7f7cefae743e1bf3bccf994f2578980fb69e2a9f00f633c2b293e928892ec289260b)",
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

## execution scope: test22_execution_scope.bc
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
symbols: ["query", "var"]

```
check if authority_fact($var);
check if block1_fact($var);
```

### validation

authorizer code:
```
```

authorizer world:
```
World {
  facts: {
    "authority_fact(1)",
    "block1_fact(1)",
    "revocation_id(0, hex:62354683692b0a865c3081e4cbd61fd35b999e3f733e9b3109c604161692d2db93a24e8d5aab05675f04e893b4f0e277c9bdc2833842f1b373d6ecb0b8dc1607)",
    "revocation_id(1, hex:6d798092e4869150cd26f7a76fb399b6bd071fc6ebd9f830d8f20db9a107357e26c77986314a22933fe78bfdcbb5bda90297e789a8fdcf4912142f0258f6d00e)",
    "revocation_id(2, hex:0582c3e7d48c0a3d9501f191cfb84bd05b3f41f302b37b57998ea7176fea49b1c598e3049382c2c155602042a7503be9c8062421a8dceb9e900f98a1f324ff07)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 2, check_id: 1, rule: "check if block1_fact($var)" })] }))`

