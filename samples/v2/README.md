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
revocation_id(0, hex:08a14cbcc6b7fdc73f484ff6a3fe6c1d4fd80c5d655e9531a39a486d70bc263f1a5ea77a6321840bd486e2e534b4a6728ecb4ccf82e62490416b2eda8e342c0d);
revocation_id(1, hex:fee2de2bae9f9cf9c6965c5ad014bd56d97a1ab8d19daf55eb725d98ebc9ad6eaceb6712c8434f6afb4347caa01572af312c8eab5c0fc1fb683e5fbb5fc1730a);
```

authorizer world:
```
World {
  facts: {
    "resource(\"file1\")",
    "revocation_id(0, hex:08a14cbcc6b7fdc73f484ff6a3fe6c1d4fd80c5d655e9531a39a486d70bc263f1a5ea77a6321840bd486e2e534b4a6728ecb4ccf82e62490416b2eda8e342c0d)",
    "revocation_id(1, hex:fee2de2bae9f9cf9c6965c5ad014bd56d97a1ab8d19daf55eb725d98ebc9ad6eaceb6712c8434f6afb4347caa01572af312c8eab5c0fc1fb683e5fbb5fc1730a)",
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
revocation_id(0, hex:a3848ba5a492586edd7b69ce1dc6c33382194dc3d944026f3a5049ee24f810d1054f5190ab2937884d6c9ccdf0b47fc6569448672df0cef5fca4a1e26dc58d00);
revocation_id(1, hex:8ac7e3634939c2aff05eac984ccc7aea2436fc7b37b09df9cda9f1f31904e9f16756914086a826951a78a9928183c3ccb9e77dfceaa861cf5ad5ddf94904490e);
revocation_id(2, hex:6c04546552ac0b8c70e6df94561915b172f1efce21b749ebab710142cfab12c584713117b9d8e0faa8080997c778bb704a52095b0789600dcdca974dc8396b07);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "owner(\"alice\", \"file1\")",
    "owner(\"alice\", \"file2\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:a3848ba5a492586edd7b69ce1dc6c33382194dc3d944026f3a5049ee24f810d1054f5190ab2937884d6c9ccdf0b47fc6569448672df0cef5fca4a1e26dc58d00)",
    "revocation_id(1, hex:8ac7e3634939c2aff05eac984ccc7aea2436fc7b37b09df9cda9f1f31904e9f16756914086a826951a78a9928183c3ccb9e77dfceaa861cf5ad5ddf94904490e)",
    "revocation_id(2, hex:6c04546552ac0b8c70e6df94561915b172f1efce21b749ebab710142cfab12c584713117b9d8e0faa8080997c778bb704a52095b0789600dcdca974dc8396b07)",
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
revocation_id(0, hex:5e1c9b2baa2711a68dfca5321807aa4442e9260ea68909d985990a8047b8abc974677085d666cbd62885d70c51a48387212440094ab4abd3c2bbe0a385ae3f07);
revocation_id(1, hex:2cac6266b01c5affb2d943110fe1286de8b9c90d3169495a93bb142b7d0e7274bd8db983320d27c06f36e7d10f58bc94a53360836a532e55ba759f67ab9e9407);
revocation_id(2, hex:23e47df948b32effec6c4fd75ba34abcd6d31d99dc3fba4e05c6d8a939a10e94b55cf7f2d27df5bda0b3455c835d2284032f32723734546b76925e835bff9e05);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:5e1c9b2baa2711a68dfca5321807aa4442e9260ea68909d985990a8047b8abc974677085d666cbd62885d70c51a48387212440094ab4abd3c2bbe0a385ae3f07)",
    "revocation_id(1, hex:2cac6266b01c5affb2d943110fe1286de8b9c90d3169495a93bb142b7d0e7274bd8db983320d27c06f36e7d10f58bc94a53360836a532e55ba759f67ab9e9407)",
    "revocation_id(2, hex:23e47df948b32effec6c4fd75ba34abcd6d31d99dc3fba4e05c6d8a939a10e94b55cf7f2d27df5bda0b3455c835d2284032f32723734546b76925e835bff9e05)",
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
revocation_id(0, hex:16d0a9d7f3d29ee2112d67451c8e4ff07bd5366a6cdb082cf4fcb66e6d15a57a22009ef1018fc4d0f9184edb0900df161807bc6f8287275f32eae6b5b1c57100);
revocation_id(1, hex:f76fa6f572a2a68010e4e49a08c78f9fdeccbd90473de5576a48bc9456b620d8a16e786c431553cf1e0de281e8d6b1da60c22f412e80a90d43d2e14f58c9f30a);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file1\")",
    "revocation_id(0, hex:16d0a9d7f3d29ee2112d67451c8e4ff07bd5366a6cdb082cf4fcb66e6d15a57a22009ef1018fc4d0f9184edb0900df161807bc6f8287275f32eae6b5b1c57100)",
    "revocation_id(1, hex:f76fa6f572a2a68010e4e49a08c78f9fdeccbd90473de5576a48bc9456b620d8a16e786c431553cf1e0de281e8d6b1da60c22f412e80a90d43d2e14f58c9f30a)",
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
revocation_id(0, hex:6475387371a58738bca267a1f5c8b713109e7e53259bc106977b88a5eb33fc5295d7c8d267954935b27b61dd7f3e9f60dfe6ee5a6eb76fdaa83aadec97a40e05);
revocation_id(1, hex:dce08dfaabbe02fa2d0449ef90e67c8817770acabcd21ebe32f8dc62b2990d5b1675af4ade1eb9e82a5687110efe40a113efcc43b23ea181c78fbd61de73990d);

check if right($0, $1), resource($0), operation($1);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:6475387371a58738bca267a1f5c8b713109e7e53259bc106977b88a5eb33fc5295d7c8d267954935b27b61dd7f3e9f60dfe6ee5a6eb76fdaa83aadec97a40e05)",
    "revocation_id(1, hex:dce08dfaabbe02fa2d0449ef90e67c8817770acabcd21ebe32f8dc62b2990d5b1675af4ade1eb9e82a5687110efe40a113efcc43b23ea181c78fbd61de73990d)",
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
revocation_id(0, hex:f2aa2478c132ca4190aef9a3bef31607d30e4f05c80e9e857a6e484857984f7950d3166fade298f3aa88879c55c27f24bca15db30bcc7d459fdea5572d877a01);

check if right($0, $1), resource($0), operation($1);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:f2aa2478c132ca4190aef9a3bef31607d30e4f05c80e9e857a6e484857984f7950d3166fade298f3aa88879c55c27f24bca15db30bcc7d459fdea5572d877a01)",
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
revocation_id(0, hex:dd0dec7cf2fb479eec0839a7cfca500633cf324eefb938a12e55e689b571c558b68ca3d3843fa6a016df8b2ec27bce5d35bfd4064654a791d59b69a0cbdc4d0a);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file1\")",
    "revocation_id(0, hex:dd0dec7cf2fb479eec0839a7cfca500633cf324eefb938a12e55e689b571c558b68ca3d3843fa6a016df8b2ec27bce5d35bfd4064654a791d59b69a0cbdc4d0a)",
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
revocation_id(0, hex:dd0dec7cf2fb479eec0839a7cfca500633cf324eefb938a12e55e689b571c558b68ca3d3843fa6a016df8b2ec27bce5d35bfd4064654a791d59b69a0cbdc4d0a);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:dd0dec7cf2fb479eec0839a7cfca500633cf324eefb938a12e55e689b571c558b68ca3d3843fa6a016df8b2ec27bce5d35bfd4064654a791d59b69a0cbdc4d0a)",
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
revocation_id(0, hex:7cf0fc712614da926a7b88edf2e9ece077d3f0c77dc7f0c671b68db4fea43c5d3c74840ad9429475723ae2fdf9b59a2fe345338bb901419f5941121231507701);
revocation_id(1, hex:f439b4ed241f963891318ae03ddcb7f76d9c00128ad3b3508e81852249118e766f2c7dda5ca347946807b0c5097aaac94498c541c22f9bf6bcf6fa54e728a103);
```

authorizer world:
```
World {
  facts: {
    "resource(\"file1\")",
    "revocation_id(0, hex:7cf0fc712614da926a7b88edf2e9ece077d3f0c77dc7f0c671b68db4fea43c5d3c74840ad9429475723ae2fdf9b59a2fe345338bb901419f5941121231507701)",
    "revocation_id(1, hex:f439b4ed241f963891318ae03ddcb7f76d9c00128ad3b3508e81852249118e766f2c7dda5ca347946807b0c5097aaac94498c541c22f9bf6bcf6fa54e728a103)",
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
revocation_id(0, hex:7cf0fc712614da926a7b88edf2e9ece077d3f0c77dc7f0c671b68db4fea43c5d3c74840ad9429475723ae2fdf9b59a2fe345338bb901419f5941121231507701);
revocation_id(1, hex:f439b4ed241f963891318ae03ddcb7f76d9c00128ad3b3508e81852249118e766f2c7dda5ca347946807b0c5097aaac94498c541c22f9bf6bcf6fa54e728a103);
```

authorizer world:
```
World {
  facts: {
    "resource(\"file2\")",
    "revocation_id(0, hex:7cf0fc712614da926a7b88edf2e9ece077d3f0c77dc7f0c671b68db4fea43c5d3c74840ad9429475723ae2fdf9b59a2fe345338bb901419f5941121231507701)",
    "revocation_id(1, hex:f439b4ed241f963891318ae03ddcb7f76d9c00128ad3b3508e81852249118e766f2c7dda5ca347946807b0c5097aaac94498c541c22f9bf6bcf6fa54e728a103)",
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
revocation_id(0, hex:39a6a882163f3ae8577ed53e533feb3f44f0e7e4e7f4a4e65c7c5df8d6f4555389e137f27358efd5f59c574edeb6d867b32221ffb00a16aa13e588b424b1c30b);
```

authorizer world:
```
World {
  facts: {
    "resource(\"file1\")",
    "revocation_id(0, hex:39a6a882163f3ae8577ed53e533feb3f44f0e7e4e7f4a4e65c7c5df8d6f4555389e137f27358efd5f59c574edeb6d867b32221ffb00a16aa13e588b424b1c30b)",
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
revocation_id(0, hex:39a6a882163f3ae8577ed53e533feb3f44f0e7e4e7f4a4e65c7c5df8d6f4555389e137f27358efd5f59c574edeb6d867b32221ffb00a16aa13e588b424b1c30b);
```

authorizer world:
```
World {
  facts: {
    "resource(\"file123.txt\")",
    "revocation_id(0, hex:39a6a882163f3ae8577ed53e533feb3f44f0e7e4e7f4a4e65c7c5df8d6f4555389e137f27358efd5f59c574edeb6d867b32221ffb00a16aa13e588b424b1c30b)",
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
revocation_id(0, hex:cbdccb19bfffbaebccac4c7eec7e2c7e5174f14fdd362cc36dc646a0a532910abda242e7be369eb63c9157c0718677ed450cb2cf85ebef1f893193e766f6300a);

check if must_be_present($0) or must_be_present($0);
```

authorizer world:
```
World {
  facts: {
    "must_be_present(\"hello\")",
    "revocation_id(0, hex:cbdccb19bfffbaebccac4c7eec7e2c7e5174f14fdd362cc36dc646a0a532910abda242e7be369eb63c9157c0718677ed450cb2cf85ebef1f893193e766f6300a)",
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
revocation_id(0, hex:2952658438834023409506b686f6a3784614ed7e0a59dd8f4007257c494ccbab493788bb0d51844bff433748f1d93a389a5c02b592d4ed67b07c1adeecc62502);
revocation_id(1, hex:54d4bd848faa41f7c96c9facf7d949b5bf80a689758eb99b8cc7b12a18e1d12bcb926266dcef0b56b6a608d0de64bc96be1810812e3271d4de3d15a937aa5002);
```

authorizer world:
```
World {
  facts: {
    "check1(\"test\")",
    "revocation_id(0, hex:2952658438834023409506b686f6a3784614ed7e0a59dd8f4007257c494ccbab493788bb0d51844bff433748f1d93a389a5c02b592d4ed67b07c1adeecc62502)",
    "revocation_id(1, hex:54d4bd848faa41f7c96c9facf7d949b5bf80a689758eb99b8cc7b12a18e1d12bcb926266dcef0b56b6a608d0de64bc96be1810812e3271d4de3d15a937aa5002)",
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
revocation_id(0, hex:7fb90d58685eb610713a02ea31d602d8ce220bbe8be83a35900d93f156e0d4d18d81616123a3b01f9aefc318239011c67ec5ec4c492b30e9a871399e8896950c);
```

authorizer world:
```
World {
  facts: {
    "revocation_id(0, hex:7fb90d58685eb610713a02ea31d602d8ce220bbe8be83a35900d93f156e0d4d18d81616123a3b01f9aefc318239011c67ec5ec4c492b30e9a871399e8896950c)",
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
revocation_id(0, hex:eb1f81c754303090748dc37d83cc710de6dd39708328928f72472683ef253f23d769bf58e7b9ecac1fd9331b18175feb24c3d33dd38357e78f4a0d5580d6c800);
revocation_id(1, hex:3f3a43a64e9f77e0afebbddd390cbd665cafee898d3558ca78363df1aa9cc5d1be41fe28b01e62ad9358e24e4c1f79b2ceeb211ffcc20d446ba9a88543a0bf03);
```

authorizer world:
```
World {
  facts: {
    "operation(\"write\")",
    "revocation_id(0, hex:eb1f81c754303090748dc37d83cc710de6dd39708328928f72472683ef253f23d769bf58e7b9ecac1fd9331b18175feb24c3d33dd38357e78f4a0d5580d6c800)",
    "revocation_id(1, hex:3f3a43a64e9f77e0afebbddd390cbd665cafee898d3558ca78363df1aa9cc5d1be41fe28b01e62ad9358e24e4c1f79b2ceeb211ffcc20d446ba9a88543a0bf03)",
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
revocation_id(0, hex:b42231acf5bcd6b48bc2bed7189cb7d0f42e07585188f94a1978b121c3b71969ee149b6948d31b3f0eabe735e131e008516aff0539f84420276bc5cebfcfd906);
revocation_id(1, hex:3482e9af639de8aee1de2ee2ecfb9b0aaae5f3ff7a1a173f2fa4c87184110173a62ee0cce216cb5eaafaf805ccd7c653149ab9f6f5ce368c52f29b2badb9f90e);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "operation(\"write\")",
    "revocation_id(0, hex:b42231acf5bcd6b48bc2bed7189cb7d0f42e07585188f94a1978b121c3b71969ee149b6948d31b3f0eabe735e131e008516aff0539f84420276bc5cebfcfd906)",
    "revocation_id(1, hex:3482e9af639de8aee1de2ee2ecfb9b0aaae5f3ff7a1a173f2fa4c87184110173a62ee0cce216cb5eaafaf805ccd7c653149ab9f6f5ce368c52f29b2badb9f90e)",
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
revocation_id(0, hex:a3436bb24e9809510c2aacf23f9d5cc06d46c5a54af6cc9ed796abb148403503c07a49474557f239eeec773bb7cc07376dc2d42213d9225415abbc77702dae09);
revocation_id(1, hex:43466cca6e79f58b18e69cd6d25f14e6f0e07b1f71bfd0ff13d44fda9c0f2169ee7a05749e59c20c9edff3b0998fb19f45ce51cbecfdc45f24b6bf98efa56f00);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file1\")",
    "revocation_id(0, hex:a3436bb24e9809510c2aacf23f9d5cc06d46c5a54af6cc9ed796abb148403503c07a49474557f239eeec773bb7cc07376dc2d42213d9225415abbc77702dae09)",
    "revocation_id(1, hex:43466cca6e79f58b18e69cd6d25f14e6f0e07b1f71bfd0ff13d44fda9c0f2169ee7a05749e59c20c9edff3b0998fb19f45ce51cbecfdc45f24b6bf98efa56f00)",
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
revocation_id(0, hex:31e5d9df576e2d54ed6d5bdad69cb0928b7d6893d90a9ab22343c132ab618a7454d2059a77f0aae7e61249fe1908a1ddb04d2645b494da02cdac8ed9f9a29107);

check if ns::fact_123("hello é	😁");
```

authorizer world:
```
World {
  facts: {
    "ns::fact_123(\"hello é\t😁\")",
    "revocation_id(0, hex:31e5d9df576e2d54ed6d5bdad69cb0928b7d6893d90a9ab22343c132ab618a7454d2059a77f0aae7e61249fe1908a1ddb04d2645b494da02cdac8ed9f9a29107)",
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
```

### validation

authorizer code:
```
revocation_id(0, hex:dabb7816ea8ba2e5b647ffc1a0eada744e7da4753f35bc845424066b5d56572a180626c865d6143980ba6e311804a93d36677573548958379a59ee5b1d068306);

check if read(0), write(1), resource(2), operation(3), right(4), time(5), role(6), owner(7), tenant(8), namespace(9), user(10), team(11), service(12), admin(13), email(14), group(15), member(16), ip_address(17), client(18), client_ip(19), domain(20), path(21), version(22), cluster(23), node(24), hostname(25), nonce(26);
```

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
    "read(0)",
    "resource(2)",
    "revocation_id(0, hex:dabb7816ea8ba2e5b647ffc1a0eada744e7da4753f35bc845424066b5d56572a180626c865d6143980ba6e311804a93d36677573548958379a59ee5b1d068306)",
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
    "check if read(0), write(1), resource(2), operation(3), right(4), time(5), role(6), owner(7), tenant(8), namespace(9), user(10), team(11), service(12), admin(13), email(14), group(15), member(16), ip_address(17), client(18), client_ip(19), domain(20), path(21), version(22), cluster(23), node(24), hostname(25), nonce(26)",
}
  policies: {
    "allow if true",
}
}
```

result: `Ok(0)`

