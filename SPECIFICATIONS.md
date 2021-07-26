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
- block: a list of datalog facts and rules. The first block is the authority
block. The other blocks define caveats
- authority: list of facts and rules defining the initial rights of the token
- ambient: list of facts related to the operation, like which resource is accessed,
the current date, or revocation lists
- symbol: string that is stored in a table and referred to by its index to save space


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
- *symbol*
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
- symbol: `#a`
- variable: `$variable` (the variable name is converted to an integer id through the symbol table)
- integer: `12`
- string: `"hello"`
- byte array: `hex:01A2`
- date in RFC 3339 format: `1985-04-12T23:20:50.52Z`
- boolean: `true` or `false`
- set: `[ #a, #b, #c]`

As an example, assuming we have the following facts: `parent(#a, #b)`,
`parent(#b, #c)`, `#parent(#c, #d)`. If we apply the rule
`grandparent($x, $z) <- parent($x, $y), parent($y, $z)`, we will try to replace
the predicates in the body by matching facts. We will get the following
combinations:
- `grandparent(#a, #c) <- parent(#a, #b), parent(#b, #c)`
- `grandparent(#b, #d) <- parent(#b, #c), parent(#c, #d)`

The system will now contain the two new facts `grandparent(#a, #c)` and
`grandparent(#b, #d)`. Whenever we generate new facts, we have to reapply all of
the system's rules on the facts, because some rules might give a new result. Once
rules application does not generate any new facts, we can stop.

#### Data types

A *symbol* indicates a value that supports equality, set inclusion and set
exclusion checks. Its internal representation is an index into the token's
symbol table, which is a list of strings. The symbol table reduces the size of
tokens by storing common symbols in a predefined table, and writing new symbols
only once per token.

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

### Authority and ambient facts

Facts in Biscuit's language have some specific context.

Authority facts can only be created in the authority block, either directly
or from rules, and are represented by the `#authority` symbol as the first
element of a fact. They hold the initial rights for the token.

Ambient facts can only be provided by the verifier, and are represented by the
`#ambient` symbol as the first element of a fact. They indicate data related
to the operation the token is authorizing.

Facts can also be created in blocks other than the authority block, but they cannot
be authority or ambient facts.

### Checks

Checks are logic queries evaluating conditions on authority and ambient facts.
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
  right(#authority, "file1", #read);
  right(#authority, "file2", #read);
  right(#authority, "file1", #write);
----------
Block 1:
check if
  resource(#ambient, $0),
  operation(#ambient, #read),
  right(#authority, $0, #read)  // restrict to read operations
----------
Block 2:
check if
  resource(#ambient, "file1")  // restrict to file1 resource
```

The facts with the `authority` tag can only be defined in the `authority` part of
the token.
The verifier side provides the `resource` and `operation` facts with the `ambient`
fact, with information from the request.

If the verifier provided the facts `resource(#ambient, "file2")` and
`operation(#ambient, #read)`, the rule application of the first check would see
`resource(#ambient, "file2"), operation(#ambient, #read), right(#authority, "file2", #read)`
with `X = "file2"`, so it would succeed, but the second check would fail
because it expects `resource(#ambient, "file1")`.

If the verifier provided the facts `resource(#ambient, "file1")` and
`operation(#ambient, #read)`, both checks would succeed.

#### Broad authority rules

In this example, we have a token with very large rights, that will be attenuated
before giving to a user. The authority block can define rules that will generate
facts depending on ambient data. This helps reduce the size of the token.

```
authority:

// if there is an ambient resource and we own it, we can read it
right(#authority, $0, #read) <- resource(#ambient, $0), owner(#ambient, $1, $0);
// if there is an ambient resource and we own it, we can write to it
right(#authority, $0, #write) <- resource(#ambient, $0), owner(#ambient, $1, $0);
----------
Block 1:

check if
  right(#authority, $0, $1),
  resource(#ambient, $0),
  operation(#ambient, $1)
----------
Block 2:

check if
  resource(#ambient, $0),
  owner(#alice, $0) // defines a token only usable by alice
```

These rules will define authority facts depending on ambient data.
If we had the ambient facts `resource(#ambient, "file1")` and
`owner(#ambient, #alice, "file1")`, the authority rules will define
`right(#authority, "file1", #read)` and `right(#authority, "file1", #write)`,
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

right(#authority, "/folder/file1", #read);
right(#authority, "/folder/file2", #read);
right(#authority, "/folder2/file3", #read);
----------
check if resource(#ambient, $0), right(#authority, $0, $1)
----------
check if time(#ambient, $0), $0 < 2019-02-05T23:00:00Z // expiration date
----------
check if source_IP(#ambient, $0), ["1.2.3.4", "5.6.7.8"].contains($0) // set membership
----------
check if resource(#ambient, $0), $0.starts_with("/folder/") // prefix operation on strings
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
- *equal*, defined on integers, strings, byte arrays, dates, symbols, set, returns a boolean
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

A `Biscuit` or `SealedBiscuit` contains in its`authority` and `blocks` fields
some byte arrays that must be deserialized as a `Block`.

#### Verification process

The verifier will first create a default symbol table, and will append to that table the values
from the `symbols` field of each block, starting from the `authority` block and all the
following blocks, ordered by their index.

The verifier will create a Datalog "world", and add to this world:
- the facts from the authority block
- the rules from the authority block
- for each following block:
  - add the facts from the block. If it finds an `authority` or `ambient` fact, it stops there and
  returns an error
  - add the rules from the block.  If it finds a rule generating `authority` or `ambient` facts, it
  stops there and returns an error checking that those facts are not `authority` or `ambient` facts

##### Revocation identifiers

Each token can be identified (and thus revoked) with a two series of ids (two per block, including the authority block). The first ids, _content-based ids_ identify a token based on its public keys and block contents (two tokens generated with the same root key and authority block will have the same content-based id). The second ids, _unique ids_ identify each token in a unique fashion (two tokens generated with the same root key and authority block will have different unique ids).

Each revocation ids identifies the token itself and all its children (tokens generated by appending blocks to it).

###### Content-based identifiers

The verifier will generate a list of facts indicating revocation identifiers for
the token. They are calculated as follows:
- perform a SHA256 hash of the authority block and the root key
- generate the hash value, store it as `revocation_id(0, <byte array of the hash)`
- for each following block:
  - continue from the previous hash, update with the current block and its public key
  - generate the hash value, store it as `revocation_id(<block index>, <byte array of the hash)`

###### Unique identifiers

In addition to content-based identifiers which only depend on the public keys and contents, the verifier will generate a list of facts indicating _unique_ revocation identfiers for the token. They are calculated as follows:
- perform a SHA256 hash of the authority block, the root key, and the 0th parameter of the signature
- generate the hash value, store it as `unique_revocation_id(0, <byte array of the hash>)`
- for each following block:
  - continue from the previous hash, update with the current block, its public key and the nth parameter of the signature
  - generate the hash value, store it as `unique_revocation_id(<block index>, <byte array of the hash>)`



##### Verifying

From there, the verifier can start loading ambient data. First, each block contains a `context`
field that can give some information on the verifier to know which data to load (to avoid
loading all of the users, groups, resources, etc). This field is a text field with no restriction
on its format.
The verifier then adds facts and rules obtained from looking up the context, and provides
facts and rules with the `ambient` tag to describe the request.

To perform the verification, the verifier will:
- run the Datalog engine on the facts and rules that were loaded
- create an error list
- for each verifier check (check provided on the verifier side), validate it. If it fails,
add an error to the error list
- for each block:
  - for each check, validate it. If it fails, add an error to the error list
- if the error list is not empty, return the error list
- for each allow/deny policy:
  - run the query. If it succeeds:
    - if it is an allow policy, the verification succeeds, stop here
    - if it is a deny policy, the verification fails, stop here
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
  required bytes authority = 1;
  repeated bytes blocks = 2;
  repeated bytes keys = 3;
  required Signature signature = 4;
}

message Signature {
  repeated bytes parameters = 1;
  required bytes z = 2;
}
```

The `keys` and `parameters` arrays contain Ristretto points in their
canonical representation, serialized to a 32 bytes array[CompressedRistretto].
Thee `z` field is a 32 bytes array containing the canonical representation
of an element of Ristretto's scalar field[Scalar].

The `keys` field contains the public keys used to sign each block. It contains
as many elements as the `blocks` field plus one. The first element is the root key.

The `parameters` field must have as many elements as the `keys` field. All of
their elements must be distinct.

or the "sealed" Biscuit wrapper (a token that cannot be attenuated offline):

```proto
message SealedBiscuit {
  required bytes authority = 1;
  repeated bytes blocks = 2;
  required bytes signature = 3;
}
```

The signature part of those tokens covers the content of authority and
blocks members.

Those members are byte arrays, containing `Block` structures serialized
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

#### Attenuable tokens

Those tokens are based on public key cryptography, specifically aggregated
gamma signatures[Aggregated Gamma Signatures]. Signature aggregation allows
Biscuit to make a new token with a valid signature from an existing one,
by signing the new data and adding the new signature to the old one.

Every public key operation in Biscuit is defined over the Ristretto prime
order group[Ristretto], that is designed to prevent some implementation
mistakes.

Definitions:
- `R`: Ristretto group
- `l`: order of the Ristretto group
- `Z/l`: scalar of order `l` associated to the Ristretto group
- `P`: Ristretto base point
- `H1`: point hashing function
- `H2`: message hashing function

##### Key generation

Private key:
`x <- Z/l*` chosen at random

Public key:
`X = sk * P`

##### Signature (one block)

With secret key `x`, public key `X`, message `message`:

* `r <- Z/l*` chosen at random
* `A = r * P`
* `d = H1(A)`
* `e = H2(X, message)`
* `z = rd - ex mod l`

The signature is `([A], z)`. The `[A]` array corresponds to the `parameters`
field in the protobuf schema.

#### Signature (appending)
With `([A0, ..., An], s)` the current signature:

Same process as the signature for a single block,
with secret key `x`, public key `X`, message `message`:

* `r <- Z/l*` chosen at random
* `A = r * P`
* `d = H1(A)`
* `e = H2(X, message)`
* `z = rd - ex mod l`

The new signature is `([A0, ..., An, A], s + z)`

#### Verifying

With:

* `([A0, ..., An], s)` the current signature
* `[P0, ..., Pn]` the list of public keys
* `[m0, ..., mn]` the list of messages

We verify as follows:
* check that `|[A0, ..., An]| == |[P0, ..., Pn]| == |[m0, ..., mn]|`
* check that `P0` is the root public key we are expecting
* check that `[A0, ..., An]` are distinct
* check that `[(P0, m0), ..., (Pn, mn)]` are distinct
* `X = H2(P0, m0) * P0 + ... + H2(Pn, mn) * Pn - ( H1(A0) * A0 + ... + H1(An) * An )`
* if `s * P + X` is the point at infinite, the signature is verified

##### Point hashing

`H1(X) = Scalar::from_hash(sha512(X.compress().to_bytes()))`

##### Message hashing

`H2(X, message) = Scalar::from_hash(sha512(X.compress().to_bytes()|message))` (with `|` the concatenation operator)

#### Sealed tokens

A sealed token contains the same kind of block as regular tokens,
but it cannot be attenuated offline, and can only be verified by
knowing the secret used to create it.

The signature is the HMAC-SHA256 hash of the secret key and the
concatenation of all the blocks.

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
The authority block can contain facts marked with the `#authority`
symbol as first id, and rules that generate facts marked with
the `#authority` symbol.

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
 - Aggregated Gamma Signatures: "Aggregation of Gamma-Signatures and Applications to Bitcoin, Yunlei Zhao" https://eprint.iacr.org/2018/414.pdf
 - Ristretto: "Ristretto: prime order elliptic curve groups with non-malleable encodings" https://ristretto.group
 - Scalar: https://doc.dalek.rs/curve25519_dalek/scalar/struct.Scalar.html
 - CompressedRistretto: https://doc.dalek.rs/curve25519_dalek/ristretto/struct.CompressedRistretto.html

