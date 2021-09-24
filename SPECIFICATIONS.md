# Biscuit, a bearer token with offline attenuation and decentralized verification

## Introduction

Biscuit is a bearer token that supports offline attenuation, can be verified
by any system that knows the root public key, and provides a flexible
caveat language based on logic programming. It is serialized as
Protocol Buffers [Protobuf], and designed to be small enough for storage in
HTTP cookies.

### Vocabulary

- Datalog: a declarative logic language that works on facts defining data relationship,
rules creating more facts if conditions are met, and queries to test such conditions
- check: a restriction on the kind of operation that can be performed with
the token that contains it, represented as a datalog query in biscuit. For the operation
to be valid, all of the checks defined in the token and the verifier must succeed
- allow/deny policies: a list of datalog queries that are tested in a sequence
until one of them matches. They can only be defined in the verifier
- block: a list of datalog facts, rules and checks. The first block is the authority
block, used to define the basic rights of a token


### Overview

A Biscuit token is defined as a series of blocks. The first one, named "authority block",
contains rights given to the token holder. The following blocks contain checks that
reduce the token's scope, in the form of logic queries that must succeed.
The holder of a biscuit token can at any time create a new token by adding a
block with more checks, thus restricting the rights of the new token, but they
cannot remove existing blocks without invalidating the signature.

The token is protected by public key cryptography operations: the initial creator
of a token holds a secret key, and any verifier for the token needs only know
the corresponding public key.
Any attenuation operation will employ ephemeral key pairs that are meant to be
destroyed as soon as they are used.

There is also a sealed version of that token that uses symmetric cryptography
to generate a token that cannot be further attenuated, but is faster to verify.

The logic language used to design rights, checks, and operation data is a
variant of datalog that accepts expressions on some data types.


## Semantics

A biscuit is structured as an append-only list of blocks, containing *checks*,
and describing authorization properties.  As with Macaroons[MACAROONS],
an operation must comply with all checks in order to be allowed by the biscuit.

Checks are written as queries defined in a flavor of Datalog that supports
expressions on some data types[DATALOG], without support for negation. This
simplifies its implementation and makes the check more precise.

### Logic language

#### Terminology

A Biscuit Datalog program contains *facts* and *rules*, which are made of
*predicates* over the following types:
- *variable*
- *integer*
- *string*
- *byte array*
- *date*
- *boolean*
- *set* a deduplicated list of values of any type, except *vaiable* or *set*

While a Biscuit token does not use a textual representation for storage, we
use one for parsing and pretty printing of Datalog elements.
A *predicate* has the form `Predicate(v0, v1, ..., vn)`.
A *fact* is a *predicate* that does not contain any *variable*.
A *rule* has the form:
`Pr(r0, r1, ..., rk) <- P0(t1_1, t1_2, ..., t1_m1), ..., Pn(tn_1, tn_2, ..., tn_mn), E0(v0, ..., vi), ..., Ex(vx, ..., vy)`.
The part of the left of the arrow is called the *head* and on the right, the
*body*. In a *rule*, each of the `ri` or `ti_j` terms can be of any type. A
*rule* is safe if all of the variables in the head appear somewhere in the body.
We also define an *expression* `Ex` over the variables `v0` to `vi`. *Expressions*
define a test of variable values when applying the *rule*. If the *expression*
returns `false`, the *rule* application fails.
A *query* is a type of *rule* that has no head. It has the following form:
`?- P0(t1_1, t1_2, ..., t1_m1), ..., Pn(tn_1, tn_2, ..., tn_mn), C0(v0), ..., Cx(vx)`.
When applying a *rule*, if there is a combination of *facts* that matches the
body's predicates, we generate a new *fact* corresponding to the head (with the
variables bound to the corresponding values).
A *check* is a *query* for which the token validation will fail if it cannot
produce any fact. If any of the cheks fails, the entire verification fails.
An *allow policy* or *deny policy* is a *query*. If the query produces something,
the policy matches, and we stop there, otherwise we test the next one. If an
*allow policy* succeeds, the token verification succeeds, while if a *deny policy*
succeeds, the token verification fails. Those policies are tested after all of
the *checks* have passed.
We will represent the various types as follows:
- variable: `$variable` (the variable name is converted to an integer id through the symbol table)
- integer: `12`
- string: `"hello"`
- byte array: `hex:01A2`
- date in RFC 3339 format: `1985-04-12T23:20:50.52Z`
- boolean: `true` or `false`
- set: `[ "a", "b", "c"]`

As an example, assuming we have the following facts: `parent("a", "b")`,
`parent("b", "c")`, `parent("c", "d")`. If we apply the rule
`grandparent($x, $z) <- parent($x, $y), parent($y, $z)`, we will try to replace
the predicates in the body by matching facts. We will get the following
combinations:
- `grandparent("a", "c") <- parent("a", "b"), parent("b", "c")`
- `grandparent("b", "d") <- parent("b", "c"), parent("c", "d")`

The system will now contain the two new facts `grandparent("a", "c")` and
`grandparent("b", "d")`. Whenever we generate new facts, we have to reapply all of
the system's rules on the facts, because some rules might give a new result. Once
rules application does not generate any new facts, we can stop.

#### Data types

An *integer* is a signed 64 bits integer. It supports the following
operatios: lower, larger, lower or equal, larger or equal, equal, set
inclusion and set exclusion.

A *string* is a suite of UTF-8 characters. It supports the following
operations: prefix, suffix, equal, set inclusion, set exclusion, regular expression.

A *byte array* is a suite of bytes. It supports the following
operations: equal, set inclusion, set exclusion.

A *date* is a 64 bit unsigned integer representing a TAI64. It supports the
following operations: before, after.

A *boolean* is `true` or `false`.

A *set* is a deduplicated list of terms of the same type. It cannot contain
variables or other sets.

### Scopes

Since the first block defines the token's rights through facts and rules, and
later blocks can define their own facts and rules, we must ensure the token
cannot increase its rights with later blocks.

This is done through execution scopes: a block's rules and checks can only
apply on facts created in the current or previous blocks. Facts, rules, checks
and policies of the verifier are executed in the context of the authority block.

Example:
- the token contains `right("file1", "read")` in the first block
- the token holder adds a block with the fact `right("file2", "read")`
- the verifier adds:
  - `resource("file2")`
  - `operation("read")`
  - `check if resource($res), operation($op), right($res, $op)`

The verifier's check will fail because when it is evaluated, it only sees
`right("file1", "read")` from the authority block.

### Checks

Checks are logic queries evaluating conditions on facts.
To validate an operation, all of a token's checks must succeed.

One block can contain one or more checks.

Their text representation is `check if` followed by the body of the query.
There can be multiple queries inside of a check, it will succeed if any of them
succeeds

Their text representation is `check if` followed by the body of the query.
There can be multiple queries inside of a check, it will succeed if any of them
succeeds. They are separated by a `or` token.

Here are some examples of writing checks:

#### Basic token

This first token defines a list of authority facts giving `read` and `write`
rights on `file1`, `read` on `file2`. The first caveat checks that the operation
is `read` (and will not allow any other `operation` fact), and then that we have
the `read` right over the resource.
The second caveat checks that the resource is `file1`.

```
authority:
  right("file1", "read");
  right("file2", "read");
  right("file1", "write");
----------
Block 1:
check if
  resource($0),
  operation("read"),
  right($0, "read")  // restrict to read operations
----------
Block 2:
check if
  resource("file1")  // restrict to file1 resource
```

The verifier side provides the `resource` and `operation` facts with information
from the request.

If the verifier provided the facts `resource("file2")` and
`operation("read")`, the rule application of the first check would see
`resource("file2"), operation("read"), right("file2", "read")`
with `X = "file2"`, so it would succeed, but the second check would fail
because it expects `resource("file1")`.

If the verifier provided the facts `resource("file1")` and
`operation("read")`, both checks would succeed.

#### Broad authority rules

In this example, we have a token with very large rights, that will be attenuated
before giving to a user. The authority block can define rules that will generate
facts depending on data provided by the verifier. This helps reduce the size of
the token.

```
authority:

// if there is an ambient resource and we own it, we can read it
right($0, "read") <- resource($0), owner($1, $0);
// if there is an ambient resource and we own it, we can write to it
right($0, "write") <- resource($0), owner($1, $0);
----------
Block 1:

check if
  right($0, $1),
  resource($0),
  operation($1)
----------
Block 2:

check if
  resource($0),
  owner("alice", $0) // defines a token only usable by alice
```

These rules will define authority facts depending on verifier data.
If we had the facts `resource("file1")` and
`owner("alice", "file1")`, the authority rules will define
`right"file1", "read")` and `right("file1", "write")`,
which will allow check 1 and check 2 to succeed.

If the owner ambient fact does not match the restriction in the second check, the
token verification will fail.

### Allow/deny policies

Allow and deny policies are queries that are tested one by one, after all of the
checks have succeeded. If one of them succeeds, we stop there, otherwise we test
the next one. If an allow policy succeeds, token verification succeeds, while if
a deny policy succeeds, the token verification fails. If none of these policies
are present, the verification will fail.

They are written as `allow if` or `deny if` followed by the body of the query.

### Expressions

We can define queries or rules with expressions on some predicate values, and
restrict usage based on ambient values:

```
authority:

right("/folder/file1", "read");
right("/folder/file2", "read");
right("/folder2/file3", "read");
----------
check if resource($0), right($0, $1)
----------
check if time($0), $0 < 2019-02-05T23:00:00Z // expiration date
----------
check if source_IP($0), ["1.2.3.4", "5.6.7.8"].contains($0) // set membership
----------
check if resource($0), $0.starts_with("/folder/") // prefix operation on strings
```

Executing an expression must always return a boolean, and all variables
appearing in an expression must also appear in other predicates of the
rule.

#### Execution

Expressions are internally represented as a serie of opcodes for a stack based
virtual machine. There are three kinds of opcodes:
- *value*: a raw value of any type. If it is a variable, the variable must also
appear in a predicate, so the variable gets a real value for execution. When
encountering a *value* opcode, we push it onto the stack
- *unary operation*: an operation that applies on one argument. When executed,
it pops a value from the stack, applies the operation, then pushes the result
- *binary operation*: an operation that applies on two arguments. When executed,
it pops two values from the stack, applies the operation, then pushes the result

After executing, the stack must contain only one value, of the boolean type.

Here are the currently defined unary operations:
- *negate*: boolean negation
- *parens*: returns its argument without modification (this is used when printing
the expression, to avoid precedence errors)
- *length*: defined on strings, byte arrays and sets

Here are the currently defined binary operations:
- *less than*, defined on integers and dates, returns a boolean
- *greater than*, defined on integers and dates, returns a boolean
- *less or equal*, defined on integers and dates, returns a boolean
- *greater or equal*, defined on integers and dates, returns a boolean
- *equal*, defined on integers, strings, byte arrays, dates, set, returns a boolean
- *contains* takes a set and another value as argument, returns a boolean. Between two sets, indicates if the first set is a superset of the second one
- *prefix*, defined on strings, returns a boolean
- *suffix*, defined on strings, returns a boolean
- *regex*, defined on strings, returns a boolean
- *add*, defined on integers, returns an integer
- *sub*, defined on integers, returns an integer
- *mul*, defined on integers, returns an integer
- *div*, defined on integers, returns an integer
- *and*, defined on booleans, returns a boolean
- *or*, defined on booleans, returns a boolean
- *intersection*, defined on sets, return a set that is the intersection of both arguments
- *union*, defined on sets, return a set that is the union of both arguments

Integer operations must have overflow checks. If it overflows, the expression
fails.

#### Example

The expression `1 + 2 < 4` will translate to the following opcodes: 1, 2, +, 4, <

Here is how it would be executed:

```
Op | stack
   | [ ]
1  | [ 1 ]
2  | [ 2, 1 ]
+  | [ 3 ]
4  | [ 4, 3 ]
<  | [ true ]
```

The stack contains only one value, and it is `true`: the expression succeeds.

### Verifier

The verifier provides information on the operation, such as the type of access
("read", "write", etc), the resource accessed, and more ambient data like the
current time, source IP address, revocation lists.
The verifier can also provide its own checks. It provides allow and deny policies
for the final decision on request validation.

#### Deserializing the token

The token must first be deserialized according to the protobuf format definition,
of either a `Biscuit` or `SealedBiscuit`.
The cryptographic signature must be checked immediately after deserializing. For the
`Biscuit` with a public key signature, the verifier must check that the public key of the
authority block is the root public key it is expecting.

A `Biscuit` or `SealedBiscuit` contains in its `authority` and `blocks` fields
some byte arrays that must be deserialized as a `Block`.

#### Verification process

The verifier will first create a default symbol table, and will append to that table the values
from the `symbols` field of each block, starting from the `authority` block and all the
following blocks, ordered by their index.

The verifier will create a Datalog "world", and add to this world its own facts and rules:
ambient data from the request, lists of users and roles, etc.
- the facts from the authority block
- the rules from the authority block
- for each following block:
  - add the facts from the block.
  - add the rules from the block.

##### Revocation identifiers

The verifier will generate a list of facts indicating revocation identifiers for
the token. The revocation identifier for a block is its signature (as it uniquely
identifies the block) serialized to a byte array (as in the Protobuf schema).
For each of these if, a fact `revocation_id(<index of the block>, <byte array>)` will be generated

##### Verifying

From there, the verifier can start loading data from each block. First, for the authority block:
- load facts and rules from the block
- run the Datalog engine on the facts and rules that were loaded
- for each authority check or verifier check, validate it. If it fails, add an error to the error list
- for each allow/deny policy:
  - run the query. If it succeeds:
    - if it is an allow policy, the verification succeeds, store the result and stop here
    - if it is a deny policy, the verification fails, store the result and stop here

Then, for each following block:
- remove all the previous rules (so the previous rules do not apply to new facts)
- load facts and rules from the block
- run the Datalog engine on the facts and rules that were loaded
- for each block check, validate it. If it fails, add an error to the error list

Returning the result:
- if the error list is not empty, return the error list
- check policy result:
  - if an allow policy matched, the verification succeeds
  - if a deny policy matched, the verification fails
  - if no policy matched, the verification fails

#### Queries

The verifier can also run queries over the loaded data. A query is a datalog rule,
and the query's result is the produced facts.

TODO: describe error codes

### Appending

#### deserializing

TODO: same as the verifier, but we do not need to know the root key

## Format

The current version of the format is in [schema.proto](https://github.com/CleverCloud/biscuit/blob/master/schema.proto)

The token contains two levels of serialization. The main structure that will be
transmitted over the wire is either the normal Biscuit wrapper:

```proto
message Biscuit {
  optional uint32 rootKeyId = 1;
  required SignedBlock authority = 2;
  repeated SignedBlock blocks = 3;
  required Proof proof = 4;
}

message SignedBlock {
  required bytes block = 1;
  required bytes nextKey = 2;
  required bytes signature = 3;
}

message Proof {
  oneof Content {
    bytes nextSecret = 1;
    bytes finalSignature = 2;
  }
}
```

The `rootKeyId` is a hint to decide which root public key should be used
for signature verification.
Each block contains a serialized byte array of the Datalog data (`block`),
the next public key (`nextKey`) and the signature of that block and key
by the previous key.

The `proof` field contains either the private key corresponding to the
public key in the last block (attenuable tokens) or a signature of the last
block by the private key (sealed tokens).

The `block` field is a byte array, containing a `Block` structure serialized
in Protobuf format as well:

```proto
message Block {
  required uint32 index = 1;
  repeated string symbols = 2;
  repeated FactV0 facts_v0 = 3;
  repeated RuleV0 rules_v0 = 4;
  repeated CaveatV0 caveats_v0 = 5;
  optional string context = 6;
  optional uint32 version = 7;
  repeated FactV1 facts_v1 = 8;
  repeated RuleV1 rules_v1 = 9;
  repeated CheckV1 checks_v1 = 10;
}
```

Each block contains a `version` field, indicating at which format version it
was generated. Since a Biscuit implementation at version N can receive a valid
token generated at version N-1, new implemetations must be able to recognize
older formats. Moreover, when appending a new block, they cannot convert the
old blocks to the new format (since that would invalidate the signature). So
each block must carry its own version.
An implementation must refuse token with a newer format than the one they know.
An implementation must always generate tokens at the highest version it can do.

### Version 0

This version corresponds to the initial development of Biscuit, kept for
compatibility with current deployments, and to test version updates.

It corresponds to the block fields with the `v0` suffix.
The `caveats_v0` field must be converted to version 1 checks.
Constraints are converted to expressions with binary operations.

As an example, a integer constraint with id `15`, of kind "lower", with `10` in
its `lower` field, will be converted to the serie of opcodes `$var, 10, <` with
`var` corresponding to `15` in the symbol table.

# Version 1

This is the format for the 1.0 version of Biscuit.

It transport expressions as an array of opcodes.

### Text format

When transmitted as text, a Biscuit token should be serialized to a
URLS safe base 64 string. When the context does not indicate that it
is a Biscuit token, that base 64 string should be prefixed with `biscuit:`
or `sealed-biscuit:` accordingly.

### Cryptography

Biscuit tokens are based on public key cryptography, with a chain of Ed25519
signatures. Each block contains the serialized Datalog, the next public key,
and the signature by the previous key. The token also contains the private key
corresponding to the last public key, to sign a new block and attenuate the
token, or a signature of the last block by the last private key, to seal the
token.

#### Signature (one block)

* `(pk_0, sk_0)` the root public and private Ed25519 keys
* `data_0` the serialized Datalog
* `(pk_1, sk_1)` the next key pair, generated at random
* `alg_1` the little endian representation of the signature algorithm fr `pk1, sk1` (see protobuf schema)
* `sig_0 = sign(sk_0, data_0 + alg_1 + pk_1)`

The token will contain:

```
Token {
  root_key_id: <optional number indicating the root key to use for verification>
  authority: Block {
    data_0,
    pk_1,
    sig_0,
  }
  blocks: [],
  proof: Proof {
    nextSecret: sk_1,
  },
}```

#### Signature (appending)

With a token containing blocks 0 to n:

Block n contains:
- `data_n`
- `pk_n+1`
- `sig_n`

The token also contains `sk_n+1`

We generate at random `(pk_n+2, sk_n+2)` and the signature `sig_n+1 = sign(sk_n+1, data_n+1 + alg_n+2 + pk_n+2)`

The token will contain:

```
Token {
  root_key_id: <optional number indicating the root key to use for verification>
  authority: Block_0,
  blocks: [Block_1, .., Block_n,
      Block_n+1 {
      data_n+1,
      pk_n+2,
      sig_n+1,
    }]
  proof: Proof {
    nextSecret: sk_n+2,
  },
}```

#### Verifying

For each block i from 0 to n:

- verify(pk_i, sig_i, data_i + alg_i + pk_i+1)

If all signatures are verified, extract pk_n+1 from the last block and
sk_n+1 from the proof field, and check that they are from the same
key pair.

#### Signature (appending)

With a token containing blocks 0 to n:

Block n contains:
- `data_n`
- `pk_n+1`
- `sig_n`

The token also contains `sk_n+1`

We generate the signature `sig_n+1 = sign(sk_n+1, data_n + pk_n+1 + sig_n)` (we sign
the last block with the last private key).

The token will contain:

```
Token {
  root_key_id: <optional number indicating the root key to use for verification>
  authority: Block_0,
  blocks: [Block_1, .., Block_n]
  proof: Proof {
    finalSignature: sig_n+1
  },
}
```

#### Verifying (sealed)

For each block i from 0 to n:

- verify(pk_i, sig_i, data_i+pk_i+1)

If all signatures are verified, extract pk_n+1 from the last block and
sig from the proof field, and check `verify(pk_n+1, sig_n+1, data_n+pk_n+1+sig_n)`

### Blocks

A block is defined as follows in the schema file:

```proto
message Block {
  required uint32 index = 1;
  repeated string symbols = 2;
  repeated Fact   facts = 3;
  repeated Rule   rules = 4;
  repeated Rule   caveats = 5;
  optional string context = 6;
}
```

The block index is incremented for each new block. The Block 0
is the authority block.

Each block can provide facts either from its facts list, or generate
them with its rules list.

### Symbol table

To reduce the token size and improve performance, Biscuit uses a symbol table,
a list of strings that any fact or token can refer to by index. While
running the logic engine does not need to know the content of that list,
pretty printing facts, rules and results will use it.

The symbol table is created from a default table containing, in order:
- authority
- ambient
- resource
- operation
- right
- time
- revocation_id

tokens can be created from a different default table, as long as the creator,
the verifier, and any user attenuating tokens are starting from the same
table.

#### Adding content to the symbol table

When creating a new block, we start from the current symbol table of the token.
For each fact or rule that introduces a new symbol, we add the corresponding
string to the table, and convert the fact or rule to use its index instead.

Once every fact and rule has been integrated, we set as the block's symbol table
(its `symbols` field) the symbols that were appended to the token's table.

The new token's symbol table is the list from the default table, and for each
block in order, the block's symbols.

It is important to verify that different blocks do not contain the same symbol in
their list.

## Test cases

We provide sample tokens and the expected result of their verification at
[https://github.com/CleverCloud/biscuit/tree/master/samples](https://github.com/CleverCloud/biscuit/tree/master/samples)

## References

 - ProtoBuf: https://developers.google.com/protocol-buffers/
 - DATALOG: "Datalog with Constraints: A Foundation for Trust Management Languages" http://crypto.stanford.edu/~ninghui/papers/cdatalog_padl03.pdf
 - Trust Management Languages" https://www.cs.purdue.edu/homes/ninghui/papers/cdatalog_padl03.pdf
 - MACAROONS: "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud" https://ai.google/research/pubs/pub41892

