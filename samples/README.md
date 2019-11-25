# Biscuit samples and expected results

root secret key: 8a5234381a6fb0cfe5e734c647f4829d9de1707665225b22410d3b85a3f98302
root public key: da905388864659eb785877a319fbc42c48e2f8a40af0c5baea0ef8ff7c795253

------------------------------

## basic token: test1_basic.bc
biscuit2 (1 caveat):
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "caveat1"]
	authority:
Block[0] {
		symbols: ["read", "write"]
		facts: [
			right(#authority, "file1", #read),
			right(#authority, "file2", #read),
			right(#authority, "file1", #write)]
		rules:[
			]
		caveats:[
			]
}
	blocks: [
		Block[1] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
			]
		caveats:[
			caveat1(0?) <- resource(#ambient, 0?) && operation(#ambient, #read) && right(#authority, 0?, #read) | ]
}]
}
```

validation: `Err(FailedLogic(FailedCaveats([Block(FailedBlockCaveat { block_id: 0, caveat_id: 0, rule: "caveat1(0?) <- resource(#ambient, 0?) && operation(#ambient, #read) && right(#authority, 0?, #read) | " })])))`

------------------------------

## different root key: test2_different_root_key.bc
biscuit2 (1 caveat):
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "caveat1"]
	authority:
Block[0] {
		symbols: ["read"]
		facts: [
			right(#authority, "file1", #read)]
		rules:[
			]
		caveats:[
			]
}
	blocks: [
		Block[1] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
			]
		caveats:[
			caveat1(0?) <- resource(#ambient, 0?) && operation(#ambient, #read) && right(#authority, 0?, #read) | ]
}]
}
```

validation: `Err(Format(UnknownPublicKey))`

------------------------------

## invalid signature format: test3_invalid_signature_format.bc
biscuit2 (1 caveat):
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "caveat1"]
	authority:
Block[0] {
		symbols: ["read", "write"]
		facts: [
			right(#authority, "file1", #read),
			right(#authority, "file2", #read),
			right(#authority, "file1", #write)]
		rules:[
			]
		caveats:[
			]
}
	blocks: [
		Block[1] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
			]
		caveats:[
			caveat1(0?) <- resource(#ambient, 0?) && operation(#ambient, #read) && right(#authority, 0?, #read) | ]
}]
}
```

validation: `Err(Format(DeserializationError("deserialization error: invalid size for z = 16 bytes")))`

------------------------------

## random block: test4_random_block.bc
biscuit2 (1 caveat):
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "caveat1"]
	authority:
Block[0] {
		symbols: ["read", "write"]
		facts: [
			right(#authority, "file1", #read),
			right(#authority, "file2", #read),
			right(#authority, "file1", #write)]
		rules:[
			]
		caveats:[
			]
}
	blocks: [
		Block[1] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
			]
		caveats:[
			caveat1(0?) <- resource(#ambient, 0?) && operation(#ambient, #read) && right(#authority, 0?, #read) | ]
}]
}
```

validation: `Err(Format(Signature(InvalidSignature)))`

------------------------------

## invalid signature: test5_invalid_signature.bc
biscuit2 (1 caveat):
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "caveat1"]
	authority:
Block[0] {
		symbols: ["read", "write"]
		facts: [
			right(#authority, "file1", #read),
			right(#authority, "file2", #read),
			right(#authority, "file1", #write)]
		rules:[
			]
		caveats:[
			]
}
	blocks: [
		Block[1] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
			]
		caveats:[
			caveat1(0?) <- resource(#ambient, 0?) && operation(#ambient, #read) && right(#authority, 0?, #read) | ]
}]
}
```

validation: `Err(Format(Signature(InvalidSignature)))`

------------------------------

## reordered blocks: test6_reordered_blocks.bc
biscuit2 (1 caveat):
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "caveat1"]
	authority:
Block[0] {
		symbols: ["read", "write"]
		facts: [
			right(#authority, "file1", #read),
			right(#authority, "file2", #read),
			right(#authority, "file1", #write)]
		rules:[
			]
		caveats:[
			]
}
	blocks: [
		Block[1] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
			]
		caveats:[
			caveat1(0?) <- resource(#ambient, 0?) && operation(#ambient, #read) && right(#authority, 0?, #read) | ]
}]
}
```

validation: `Err(InvalidBlockIndex(InvalidBlockIndex { expected: 1, found: 2 }))`

------------------------------

## missing authority tag: test7_missing_authority_tag.bc
biscuit2 (1 caveat):
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "write", "caveat1"]
	authority:
Block[0] {
		symbols: ["read", "write"]
		facts: [
			right(#authority, "file1", #read),
			right(#authority, "file2", #read),
			right("file1", #write)]
		rules:[
			]
		caveats:[
			]
}
	blocks: [
		Block[1] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
			]
		caveats:[
			caveat1(0?) <- operation(#ambient, #read) | ]
}]
}
```

validation: `Err(FailedLogic(InvalidAuthorityFact("right(\"file1\", #write)")))`

------------------------------

## invalid block fact with authority tag: test8_invalid_block_fact_authority.bc
biscuit2 (1 caveat):
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "caveat1", "write"]
	authority:
Block[0] {
		symbols: ["read"]
		facts: [
			right(#authority, "file1", #read)]
		rules:[
			]
		caveats:[
			]
}
	blocks: [
		Block[1] {
		symbols: ["caveat1", "write"]
		facts: [
			right(#authority, "file1", #write)]
		rules:[
			]
		caveats:[
			caveat1(0?) <- operation(#ambient, #read) | ]
}]
}
```

validation: `Err(FailedLogic(InvalidBlockFact(0, "right(#authority, \"file1\", #write)")))`

------------------------------

## invalid block fact with ambient tag: test9_invalid_block_fact_ambient.bc
biscuit2 (1 caveat):
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "caveat1", "write"]
	authority:
Block[0] {
		symbols: ["read"]
		facts: [
			right(#authority, "file1", #read)]
		rules:[
			]
		caveats:[
			]
}
	blocks: [
		Block[1] {
		symbols: ["caveat1", "write"]
		facts: [
			right(#ambient, "file1", #write)]
		rules:[
			]
		caveats:[
			caveat1(0?) <- operation(#ambient, #read) | ]
}]
}
```

validation: `Err(FailedLogic(InvalidBlockFact(0, "right(#ambient, \"file1\", #write)")))`

------------------------------

## separate block validation (facts from one block should not be usable in another one): test10_separate_block_validation.bc
biscuit3:
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "test", "write", "caveat1"]
	authority:
Block[0] {
		symbols: []
		facts: [
			]
		rules:[
			]
		caveats:[
			]
}
	blocks: [
		Block[1] {
		symbols: ["test", "write"]
		facts: [
			test(#write)]
		rules:[
			]
		caveats:[
			]
},
	Block[2] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
			]
		caveats:[
			caveat1(0?) <- test(0?) | ]
}]
}
```

validation: `Err(FailedLogic(FailedCaveats([Block(FailedBlockCaveat { block_id: 1, caveat_id: 0, rule: "caveat1(0?) <- test(0?) | " })])))`

------------------------------

## expired token: test11_expired_token.bc
biscuit2 (1 caveat):
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "caveat1", "expiration", "time"]
	authority:
Block[0] {
		symbols: []
		facts: [
			]
		rules:[
			]
		caveats:[
			]
}
	blocks: [
		Block[1] {
		symbols: ["caveat1", "expiration", "time"]
		facts: [
			]
		rules:[
			]
		caveats:[
			caveat1("file1") <- resource(#ambient, "file1") | ,
			expiration(0?) <- time(#ambient, 0?) | 0? <= 1545264000]
}]
}
```

validation: `Err(FailedLogic(FailedCaveats([Block(FailedBlockCaveat { block_id: 0, caveat_id: 1, rule: "expiration(0?) <- time(#ambient, 0?) | 0? <= 1545264000" })])))`

------------------------------

## authority rules: test12_authority_rules.bc
biscuit2 (1 caveat):
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "owner", "write", "caveat1", "caveat2", "alice"]
	authority:
Block[0] {
		symbols: ["read", "owner", "write"]
		facts: [
			]
		rules:[
			right(#authority, 1?, #read) <- resource(#ambient, 1?) && owner(#ambient, 0?, 1?) | ,
			right(#authority, 1?, #write) <- resource(#ambient, 1?) && owner(#ambient, 0?, 1?) | ]
		caveats:[
			]
}
	blocks: [
		Block[1] {
		symbols: ["caveat1", "caveat2", "alice"]
		facts: [
			]
		rules:[
			]
		caveats:[
			caveat1(0?, 1?) <- right(#authority, 0?, 1?) && resource(#ambient, 0?) && operation(#ambient, 1?) | ,
			caveat2(0?) <- resource(#ambient, 0?) && owner(#ambient, #alice, 0?) | ]
}]
}
```

validation: `Ok(())`

------------------------------

## verifier authority caveats: test13_verifier_authority_caveats.bc
biscuit:
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read"]
	authority:
Block[0] {
		symbols: ["read"]
		facts: [
			right(#authority, "file1", #read)]
		rules:[
			]
		caveats:[
			]
}
	blocks: [
		]
}
```

validation: `Err(FailedLogic(FailedCaveats([Verifier(FailedVerifierCaveat { block_id: 0, caveat_id: 0, rule: "caveat1(0?, 1?) <- right(#authority, 0?, 1?) && resource(#ambient, 0?) && operation(#ambient, 1?) | " })])))`

------------------------------

## authority caveats: test14_authority_caveats.bc
biscuit:
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "caveat1"]
	authority:
Block[0] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
			]
		caveats:[
			caveat1("file1") <- resource(#ambient, "file1") | ]
}
	blocks: [
		]
}
```

validation for "file1": `Ok(())`
validation for "file2": `Err(FailedLogic(FailedCaveats([Block(FailedBlockCaveat { block_id: 0, caveat_id: 0, rule: "caveat1(\"file1\") <- resource(#ambient, \"file1\") | " })])))`

------------------------------

## block rules: test15_block_rules.bc
biscuit2 (1 caveat):
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "read", "valid_date", "time", "caveat1"]
	authority:
Block[0] {
		symbols: ["read"]
		facts: [
			right(#authority, "file1", #read),
			right(#authority, "file2", #read)]
		rules:[
			]
		caveats:[
			]
}
	blocks: [
		Block[1] {
		symbols: ["valid_date", "time", "caveat1"]
		facts: [
			]
		rules:[
			valid_date("file1") <- time(#ambient, 0?) && resource(#ambient, "file1") | 0? <= 1924952399,
			valid_date(1?) <- time(#ambient, 0?) && resource(#ambient, 1?) | 0? <= 946645199 && 1? not in {"file1"}]
		caveats:[
			caveat1(0?) <- valid_date(0?) && resource(#ambient, 0?) | ]
}]
}
```

validation for "file1": `Ok(())`
validation for "file2": `Err(FailedLogic(FailedCaveats([Block(FailedBlockCaveat { block_id: 0, caveat_id: 0, rule: "caveat1(0?) <- valid_date(0?) && resource(#ambient, 0?) | " })])))`

------------------------------

## regex_constraint: test16_regex_constraint.bc
biscuit:
```
Biscuit {
	symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "resource_match"]
	authority:
Block[0] {
		symbols: ["resource_match"]
		facts: [
			]
		rules:[
			]
		caveats:[
			resource_match(0?) <- resource(#ambient, 0?) | 0? matches /file[0-9]+.txt/]
}
	blocks: [
		]
}
```

validation for "file1": `Err(FailedLogic(FailedCaveats([Block(FailedBlockCaveat { block_id: 0, caveat_id: 0, rule: "resource_match(0?) <- resource(#ambient, 0?) | 0? matches /file[0-9]+.txt/" })])))`
validation for "file123.txt": `Ok(())`
