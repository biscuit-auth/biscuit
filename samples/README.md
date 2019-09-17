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
}
	blocks: [
		Block[1] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
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
}
	blocks: [
		Block[1] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
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
}
	blocks: [
		Block[1] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
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
}
	blocks: [
		Block[1] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
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
}
	blocks: [
		Block[1] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
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
}
	blocks: [
		Block[1] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
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
}
	blocks: [
		Block[1] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
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
}
	blocks: [
		Block[1] {
		symbols: ["caveat1", "write"]
		facts: [
			right(#authority, "file1", #write)]
		rules:[
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
}
	blocks: [
		Block[1] {
		symbols: ["caveat1", "write"]
		facts: [
			right(#ambient, "file1", #write)]
		rules:[
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
}
	blocks: [
		Block[1] {
		symbols: ["test", "write"]
		facts: [
			test(#write)]
		rules:[
			]
},
	Block[2] {
		symbols: ["caveat1"]
		facts: [
			]
		rules:[
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
}
	blocks: [
		Block[1] {
		symbols: ["caveat1", "expiration", "time"]
		facts: [
			]
		rules:[
			caveat1("file1") <- resource(#ambient, "file1") | ,
			expiration(0?) <- time(#ambient, 0?) | 0? <= 1545264000]
}]
}
```

validation: `Err(FailedLogic(FailedCaveats([Block(FailedBlockCaveat { block_id: 0, caveat_id: 1, rule: "expiration(0?) <- time(#ambient, 0?) | 0? <= 1545264000" })])))`
