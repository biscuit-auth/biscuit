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
revocation_id(0, hex:1d5f4e65ee45896f32708462af0e82c18ca953cd2e87e340c8a5c2e4e82a45639b9853ee92442273cdebde3c0f3692597d31d116e53593c813726946cdca4205);
revocation_id(1, hex:d4a96909b2d51a25b65079bb1e91dff8047a8754da8827123ae5bfc28b121afd9cca1acb266a3162c0d1d0371ee1b9011f6bfc278cafa7dae0dbe03848bc7f03);
```

authorizer world:
```
World {
  facts: {
    "resource(\"file1\")",
    "revocation_id(0, hex:1d5f4e65ee45896f32708462af0e82c18ca953cd2e87e340c8a5c2e4e82a45639b9853ee92442273cdebde3c0f3692597d31d116e53593c813726946cdca4205)",
    "revocation_id(1, hex:d4a96909b2d51a25b65079bb1e91dff8047a8754da8827123ae5bfc28b121afd9cca1acb266a3162c0d1d0371ee1b9011f6bfc278cafa7dae0dbe03848bc7f03)",
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
revocation_id(0, hex:c471ae436d91168805955ad0667ed764fc7f2379268c638715dcfa4e00ccdba7a550f02ca1255f29773da9ecf16c8a8ca7993ebdc2788eaa0074f03169a2b301);
revocation_id(1, hex:24829d3b1e1adf1ea484e352703cae457b2e658cde3a1a01afe7c8b6827a4b4c8a847de9065f58045da9bf939f77bf5a5c340350189af281dbc9089a95259905);
revocation_id(2, hex:2468bc17a2431da4e1999aed29b7dc8d5137308a98aec879faca12a6f677306ecc4f5e9d44a49ed8319005ea2512049e4eec69fb8ecb7bbb6f8e2e3c0fc26103);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "owner(\"alice\", \"file1\")",
    "owner(\"alice\", \"file2\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:c471ae436d91168805955ad0667ed764fc7f2379268c638715dcfa4e00ccdba7a550f02ca1255f29773da9ecf16c8a8ca7993ebdc2788eaa0074f03169a2b301)",
    "revocation_id(1, hex:24829d3b1e1adf1ea484e352703cae457b2e658cde3a1a01afe7c8b6827a4b4c8a847de9065f58045da9bf939f77bf5a5c340350189af281dbc9089a95259905)",
    "revocation_id(2, hex:2468bc17a2431da4e1999aed29b7dc8d5137308a98aec879faca12a6f677306ecc4f5e9d44a49ed8319005ea2512049e4eec69fb8ecb7bbb6f8e2e3c0fc26103)",
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
revocation_id(0, hex:365b58d5fe581c5e34da38d2fce8c1f6b1ea544f19ee83106e862cf4dcd5cd92bea611b2f5d5b1170950dee243221c802b637c59614e3e40dc65dfae3d879707);
revocation_id(1, hex:db119dee84b43ef9489300a455fad700cd1e649a002fe4fa779fe5f15dc34864b42a8e0558e8c0f61bd9fd1e51c0ba3fdf2e4294357e5188697450c4e5382804);
revocation_id(2, hex:1e3cd0c672bdbf955ec1fb1dd04fd07c9c2dc78c921b52407f988a88f9735e6c650854614d171ad88d2d819ca6881d402442c9f9cdcdf14af89757f6059cd80f);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:365b58d5fe581c5e34da38d2fce8c1f6b1ea544f19ee83106e862cf4dcd5cd92bea611b2f5d5b1170950dee243221c802b637c59614e3e40dc65dfae3d879707)",
    "revocation_id(1, hex:db119dee84b43ef9489300a455fad700cd1e649a002fe4fa779fe5f15dc34864b42a8e0558e8c0f61bd9fd1e51c0ba3fdf2e4294357e5188697450c4e5382804)",
    "revocation_id(2, hex:1e3cd0c672bdbf955ec1fb1dd04fd07c9c2dc78c921b52407f988a88f9735e6c650854614d171ad88d2d819ca6881d402442c9f9cdcdf14af89757f6059cd80f)",
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
revocation_id(1, hex:2545cef5c2872ef2fe0f0e78752e1d692b6956b6018fa397ad78ca70e5cabbadc0014382390b48a7ec5811e18719e0f691cdcc3abaf3424304b03176a320120e);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file1\")",
    "revocation_id(0, hex:16d0a9d7f3d29ee2112d67451c8e4ff07bd5366a6cdb082cf4fcb66e6d15a57a22009ef1018fc4d0f9184edb0900df161807bc6f8287275f32eae6b5b1c57100)",
    "revocation_id(1, hex:2545cef5c2872ef2fe0f0e78752e1d692b6956b6018fa397ad78ca70e5cabbadc0014382390b48a7ec5811e18719e0f691cdcc3abaf3424304b03176a320120e)",
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
revocation_id(0, hex:2ea3411339db9331e8156bdb23edb2667f7b927486b36a0220b1d37c5f650907c795932b430ac31a2eb5917c6d47756c1d863bc55d70ebec307698a03ab3ff0f);
revocation_id(1, hex:5c66dfd95e2a0212f7915c5564df381e02e13b7814013de228996c929445befd549a19d71de35bb3ea15c2db808c373b805f0e848f46da4b03f13e431ee2b801);

check if right($0, $1), resource($0), operation($1);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:2ea3411339db9331e8156bdb23edb2667f7b927486b36a0220b1d37c5f650907c795932b430ac31a2eb5917c6d47756c1d863bc55d70ebec307698a03ab3ff0f)",
    "revocation_id(1, hex:5c66dfd95e2a0212f7915c5564df381e02e13b7814013de228996c929445befd549a19d71de35bb3ea15c2db808c373b805f0e848f46da4b03f13e431ee2b801)",
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
revocation_id(0, hex:e5cb2bbd5a7e91fb48766f535b230ceceab4aa98f495abab315d351a8cb3a0a07edc6730b19b1f631c7b1b6b8dfca8d8816861c1eb2e9c3978993b3d201eca0d);

check if right($0, $1), resource($0), operation($1);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:e5cb2bbd5a7e91fb48766f535b230ceceab4aa98f495abab315d351a8cb3a0a07edc6730b19b1f631c7b1b6b8dfca8d8816861c1eb2e9c3978993b3d201eca0d)",
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
revocation_id(0, hex:c9324eef7b7ac5b5af5b0be2970fe2db90797ea07cf80a1fd5a3eb7fdc8df22543ab984d7357f8a110bc7a9a92dca597a568e96a07c27fb3ae1cbe5751d0270e);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file1\")",
    "revocation_id(0, hex:c9324eef7b7ac5b5af5b0be2970fe2db90797ea07cf80a1fd5a3eb7fdc8df22543ab984d7357f8a110bc7a9a92dca597a568e96a07c27fb3ae1cbe5751d0270e)",
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
revocation_id(0, hex:c9324eef7b7ac5b5af5b0be2970fe2db90797ea07cf80a1fd5a3eb7fdc8df22543ab984d7357f8a110bc7a9a92dca597a568e96a07c27fb3ae1cbe5751d0270e);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file2\")",
    "revocation_id(0, hex:c9324eef7b7ac5b5af5b0be2970fe2db90797ea07cf80a1fd5a3eb7fdc8df22543ab984d7357f8a110bc7a9a92dca597a568e96a07c27fb3ae1cbe5751d0270e)",
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
revocation_id(0, hex:519a90ef066d3e2885ed86a76e9a3d0e68898e84f203dea515e857a2ec9611e3b471ec11b6258ed4f1f5a0d6e96dc3c842240f49c58d2a6b4da32ca0e3e14708);
revocation_id(1, hex:f34063891ed7193b4485edaee11f7afed277e1a2db65c9fc7f4d27b4f281e65f0f0b0d0b7ff052da73c7c1fddf7ba80b4ee6cfb463514e2bd4ef81d276089209);
```

authorizer world:
```
World {
  facts: {
    "resource(\"file1\")",
    "revocation_id(0, hex:519a90ef066d3e2885ed86a76e9a3d0e68898e84f203dea515e857a2ec9611e3b471ec11b6258ed4f1f5a0d6e96dc3c842240f49c58d2a6b4da32ca0e3e14708)",
    "revocation_id(1, hex:f34063891ed7193b4485edaee11f7afed277e1a2db65c9fc7f4d27b4f281e65f0f0b0d0b7ff052da73c7c1fddf7ba80b4ee6cfb463514e2bd4ef81d276089209)",
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
revocation_id(0, hex:519a90ef066d3e2885ed86a76e9a3d0e68898e84f203dea515e857a2ec9611e3b471ec11b6258ed4f1f5a0d6e96dc3c842240f49c58d2a6b4da32ca0e3e14708);
revocation_id(1, hex:f34063891ed7193b4485edaee11f7afed277e1a2db65c9fc7f4d27b4f281e65f0f0b0d0b7ff052da73c7c1fddf7ba80b4ee6cfb463514e2bd4ef81d276089209);
```

authorizer world:
```
World {
  facts: {
    "resource(\"file2\")",
    "revocation_id(0, hex:519a90ef066d3e2885ed86a76e9a3d0e68898e84f203dea515e857a2ec9611e3b471ec11b6258ed4f1f5a0d6e96dc3c842240f49c58d2a6b4da32ca0e3e14708)",
    "revocation_id(1, hex:f34063891ed7193b4485edaee11f7afed277e1a2db65c9fc7f4d27b4f281e65f0f0b0d0b7ff052da73c7c1fddf7ba80b4ee6cfb463514e2bd4ef81d276089209)",
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
revocation_id(0, hex:40e5e16383509469950240ad0d20c806e2700900133e66e6ab592da2cf90181e23fecb34083f3b78ca53851448372bd8ebd57e4ef8c287eef3164ad2dbb6b300);
```

authorizer world:
```
World {
  facts: {
    "resource(\"file1\")",
    "revocation_id(0, hex:40e5e16383509469950240ad0d20c806e2700900133e66e6ab592da2cf90181e23fecb34083f3b78ca53851448372bd8ebd57e4ef8c287eef3164ad2dbb6b300)",
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
revocation_id(0, hex:40e5e16383509469950240ad0d20c806e2700900133e66e6ab592da2cf90181e23fecb34083f3b78ca53851448372bd8ebd57e4ef8c287eef3164ad2dbb6b300);
```

authorizer world:
```
World {
  facts: {
    "resource(\"file123.txt\")",
    "revocation_id(0, hex:40e5e16383509469950240ad0d20c806e2700900133e66e6ab592da2cf90181e23fecb34083f3b78ca53851448372bd8ebd57e4ef8c287eef3164ad2dbb6b300)",
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
revocation_id(0, hex:f9ee6baab57eb5cf14ad003a7f964691ec4eea1d1ec86de95cace3056bc4cf7c12836a2fc0241acaaea9365ba1a411be69baea54a45f18ea4c66d82cc9cc5c01);

check if must_be_present($0) or must_be_present($0);
```

authorizer world:
```
World {
  facts: {
    "must_be_present(\"hello\")",
    "revocation_id(0, hex:f9ee6baab57eb5cf14ad003a7f964691ec4eea1d1ec86de95cace3056bc4cf7c12836a2fc0241acaaea9365ba1a411be69baea54a45f18ea4c66d82cc9cc5c01)",
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
revocation_id(0, hex:efd90e4a128ef2cbedf66c63331c151517f4b79320771902875d67ee4b18a55a9c22e7593eaf76fc4705f3ed46c1f847fbe3f042e05077129f9298dbdca1a10b);
revocation_id(1, hex:669e300264a304194dbb3945ceb37d5de862ad18e0dd25c4d8bd8426dc85fcab18f83a180daae0d044959198faffed3adee7a45eebe9b9e1c14a77292118dc0a);
```

authorizer world:
```
World {
  facts: {
    "check1(\"test\")",
    "revocation_id(0, hex:efd90e4a128ef2cbedf66c63331c151517f4b79320771902875d67ee4b18a55a9c22e7593eaf76fc4705f3ed46c1f847fbe3f042e05077129f9298dbdca1a10b)",
    "revocation_id(1, hex:669e300264a304194dbb3945ceb37d5de862ad18e0dd25c4d8bd8426dc85fcab18f83a180daae0d044959198faffed3adee7a45eebe9b9e1c14a77292118dc0a)",
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
revocation_id(0, hex:01356b71906d821ed72f2083465ed06afb0eb1d50412a8badd229cfc39746cda761dd9e3f8d8dda10f1b1aefb29fb8937f52326e2516c7b77bec57b4ba3d780b);
```

authorizer world:
```
World {
  facts: {
    "revocation_id(0, hex:01356b71906d821ed72f2083465ed06afb0eb1d50412a8badd229cfc39746cda761dd9e3f8d8dda10f1b1aefb29fb8937f52326e2516c7b77bec57b4ba3d780b)",
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
revocation_id(0, hex:8830178822f145eb66cb2e65668fd692d9f143612d9015ec032dba87b4e152925d60b78dbe40567c1e497d2d9892bcce99082f7e7afc461cac996887f47d1009);
revocation_id(1, hex:7f975546191401e64623ba6ccbb0317b801911860e6205d6413bd7c77b2463503138959a18231c2755642d7c37b2fb6669fe76f25e8ed2dac2da7c5a0653e401);
```

authorizer world:
```
World {
  facts: {
    "operation(\"write\")",
    "revocation_id(0, hex:8830178822f145eb66cb2e65668fd692d9f143612d9015ec032dba87b4e152925d60b78dbe40567c1e497d2d9892bcce99082f7e7afc461cac996887f47d1009)",
    "revocation_id(1, hex:7f975546191401e64623ba6ccbb0317b801911860e6205d6413bd7c77b2463503138959a18231c2755642d7c37b2fb6669fe76f25e8ed2dac2da7c5a0653e401)",
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
revocation_id(0, hex:94baf24f6d75230dd299edf408aba593bcba3099e80e9144ede2b6fce7e6d2a939f40aa6d5e8f7313d2135b411bda11632496bcbc22741169fc283f01b1aa80b);
revocation_id(1, hex:ba2174f6204dfb9fbdff4052571fa671701979385eaef97ee1cc761eb52fa63418b5ad9c7fa48c39c14f91b2e06116a9183a92be434ddc376c429787da555503);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "operation(\"write\")",
    "revocation_id(0, hex:94baf24f6d75230dd299edf408aba593bcba3099e80e9144ede2b6fce7e6d2a939f40aa6d5e8f7313d2135b411bda11632496bcbc22741169fc283f01b1aa80b)",
    "revocation_id(1, hex:ba2174f6204dfb9fbdff4052571fa671701979385eaef97ee1cc761eb52fa63418b5ad9c7fa48c39c14f91b2e06116a9183a92be434ddc376c429787da555503)",
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
revocation_id(0, hex:2f166a81e685b07754e571d7dd624e5034695b485145376c213e86d0aac44a3fc7b2f8b79b56ed07f396ee9a89430fc666440c4cf2d0ae5a4e6d82c0162ede07);
revocation_id(1, hex:397a8ada46db65ade4b7367483586060371527bff2047c337bb24462b4a4c653b32487a251a8dfcedb26ea786e327cfad1e9ddfdba84bd4b6965d375c2d9d60e);
```

authorizer world:
```
World {
  facts: {
    "operation(\"read\")",
    "resource(\"file1\")",
    "revocation_id(0, hex:2f166a81e685b07754e571d7dd624e5034695b485145376c213e86d0aac44a3fc7b2f8b79b56ed07f396ee9a89430fc666440c4cf2d0ae5a4e6d82c0162ede07)",
    "revocation_id(1, hex:397a8ada46db65ade4b7367483586060371527bff2047c337bb24462b4a4c653b32487a251a8dfcedb26ea786e327cfad1e9ddfdba84bd4b6965d375c2d9d60e)",
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
revocation_id(0, hex:3c6dd38df9982126d9581f43f29511716ba571e3b95c25dd079a451819184ec92d50edeace7b213b89726d2d74ea91a37ab91d48aa5c93bff4617bfd4019280c);

check if ns::fact_123("hello é	😁");
```

authorizer world:
```
World {
  facts: {
    "ns::fact_123(\"hello é\t😁\")",
    "revocation_id(0, hex:3c6dd38df9982126d9581f43f29511716ba571e3b95c25dd079a451819184ec92d50edeace7b213b89726d2d74ea91a37ab91d48aa5c93bff4617bfd4019280c)",
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
revocation_id(0, hex:5c2e95d83d52a9b0af91aa3fc82acdce1b62e96091f2ac5efd30688151284d0ffc3f9b52dcace4073aba8b99c62b228de3c4d4bc2baadff8eef1a1aff9b68709);

check if read(0), write(1), resource(2), operation(3), right(4), time(5), role(6), owner(7), tenant(8), namespace(9), user(10), team(11), service(12), admin(13), email(14), group(15), member(16), ip_address(17), client(18), client_ip(19), domain(20), path(21), version(22), cluster(23), node(24), hostname(25), nonce(26), query(27);
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
    "query(27)",
    "read(0)",
    "resource(2)",
    "revocation_id(0, hex:5c2e95d83d52a9b0af91aa3fc82acdce1b62e96091f2ac5efd30688151284d0ffc3f9b52dcace4073aba8b99c62b228de3c4d4bc2baadff8eef1a1aff9b68709)",
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
revocation_id(0, hex:c7e0e1b3563664312cfe8378dcd95ba04a74928cbe852241d044ba4b20fbaf649ab624619b5ab5b1b5ee8e0bd00512ca5cfbeb216fc795350789eca7aac96504);
revocation_id(1, hex:3ffaab1d6f0c1a7b6e6b0d96839749813a8c07712913a0bd90fecae47184212d061acc8fb2e20c91db647a763100bb5154759cbd854659332eeebc96d0fca40e);
revocation_id(2, hex:af61590a37c0837c91393e70652ca67e31d58e29739355dff4db2c54c1dfc62c1f6b61dd37834c839d766b701d7e7fd988f54354188482d5cdd7400b0444c505);
```

authorizer world:
```
World {
  facts: {
    "authority_fact(1)",
    "block1_fact(1)",
    "revocation_id(0, hex:c7e0e1b3563664312cfe8378dcd95ba04a74928cbe852241d044ba4b20fbaf649ab624619b5ab5b1b5ee8e0bd00512ca5cfbeb216fc795350789eca7aac96504)",
    "revocation_id(1, hex:3ffaab1d6f0c1a7b6e6b0d96839749813a8c07712913a0bd90fecae47184212d061acc8fb2e20c91db647a763100bb5154759cbd854659332eeebc96d0fca40e)",
    "revocation_id(2, hex:af61590a37c0837c91393e70652ca67e31d58e29739355dff4db2c54c1dfc62c1f6b61dd37834c839d766b701d7e7fd988f54354188482d5cdd7400b0444c505)",
}
  rules: {}
  checks: {}
  policies: {
    "allow if true",
}
}
```

result: `Err(FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 2, check_id: 1, rule: "check if block1_fact($var)" })] }))`

