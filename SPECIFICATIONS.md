# Biscuit, a bearer token with offline attenuation and decentralized verification

## Introduction

Biscuit is a bearer token that supports offline attenuation, can be verified
by any system that knows the root public key, and provides a flexible
caveat language based on logic programming. It is serialized as
Protocol Buffers [Protobuf], and designed to be small enough for storage in
HTTP cookies.

### Vocabulary

- datalog: a declarative logic language that works on facts defining data relationship,
rules creating more facts if conditions are met, and queries to test such conditions
- caveat: a restriction on the kind of operation that can be performed with
the token that contains it, represented as a datalog query in biscuit. For the operation
to be valid, all the caveats in the token must succeed
- block: a list of datalog facts and rules. The first block is the authority
block. The other blocks define caveats
- authority: list of facts and rules defining the initial rights of the token
- ambient: list of facts related to the operation, like which resource is accessed,
the current date, or revocation lists
- symbol: string that is stored in a table and referred to by its index to save space


### Overview

A Biscuit token is defined as a serie of blocks. The first one, named "authority block",
contains rights given to the token holder. The following blocks contain caveats that
reduce the token's scope, in the form of logic queries that must succeed.
The holder of a biscuit token can at any time create a new
token by adding a block with more caveats, but they cannot remove existing blocks
without invalidating the signature.

The token is protected by public key cryptography operations: the initial creator
of a token holds a secret key, and any verifier for the token needs only know
the corresponding public key.
Any attenuation operation will employ ephemeral key pairs that are meant to be
destroyed as soon as they are used.

There is also a sealed version of that token that uses symmetric cryptography
to generate a token that cannot be further attenuated, but is faster to verify.

The logic language used to design rights, caveats and operation data is a
variant of datalog that accepts constraints on some data types.


## Semantics

A biscuit is structured as an append-only list of blocks, containing *caveats*,
and describing authorization properties.  As with Macaroons[MACAROONS],
an operation must comply with all caveats in order to be allowed by the biscuit.

Caveats are written as queries defined in a flavor of Datalog that supports
constraints on some data types[DATALOG], without support for negation. This
simplifies its implementation and makes the caveat more precise.

### Logic language

#### Terminology

A Biscuit Datalog program contains *facts* and *rules*, which are made of
*predicates* over the following types: *symbol*, *variable*, *integer*,
*string*, *byte array* and *date*. While Biscuit does not use a textual
representation for storage, we will use one for this specification and
for pretty printing of caveats.
A *predicate* has the form `Predicate(v0, v1, ..., vn)`.
A *fact* is a *predicate* that does not contain any *variable*.
A *rule* has the form:
`Pr(r0, r1, ..., rk) <- P0(t1_1, t1_2, ..., t1_m1), ..., Pn(tn_1, tn_2, ..., tn_mn), C0(v0, ..., vi), ..., Cx(vx, ..., vy)`.
The part of the left of the arrow is called the *head* and on the right, the
*body*. In a *rule*, each of the `ri` or `ti_j` terms can be of any type. A
*rule* is safe if all of the variables in the head appear somewhere in the body.
We also define an *expression* `Cx` over the variables `v0` to `vi`. *Expressions*
define a test of variable values when applying the *rule*. If the *expression*
returns `false`, the *rule* application fails.
A *query* is a type of *rule* that has no head. It has the following form:
`?- P0(t1_1, t1_2, ..., t1_m1), ..., Pn(tn_1, tn_2, ..., tn_mn), C0(v0), ..., Cx(vx)`.
When applying a *rule*, if there is a combination of *facts* that matches the
body's predicates, we generate a new *fact* corresponding to the head (with the
variables bound to the corresponding values).
We will represent the various types as follows:
- symbol: `#a`
- variable: `$variable` (the variable name is converted to an integer id through the symbol table)
- integer: `12`
- string: `"hello"`
- byte array: `hex:01A2`
- date in RFC 3339 format: `1985-04-12T23:20:50.52Z`

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

### Caveats

Caveats are logic queries evaluating conditions on authority and ambient facts.
To validate an operation, all of a token's caveats must succeed.

One block can contain one or more caveats.

Here are some examples of writing caveats:

#### Basic token

This first token defines a list of authority facts giving `read` and `write`
rights on `file1`, `read` on `file2`. The first caveat checks that the operation
is `read` (and will not allow any other `operation` fact), and then that we have
the `read` right over the resource.
The second caveat checks that the resource is `file1`.

```
authority = [right(#authority, "file1", #read), right(#authority, "file2", #read),
  right(#authority, "file1", #write)]
----------
caveats = [caveat() <- resource(#ambient, $0), operation(#ambient, #read),
  right(#authority, $0, #read)]  // restrict to read operations
----------
caveats = [caveat() <- resource(#ambient, "file1")]  // restrict to file1 resource
```

The facts with the `authority` tag can only be defined in the `authority` part of
the token.
The verifier side provides the `resource` and `operation` facts with the `ambient`
fact, with information from the request.

If the verifier provided the facts `resource(#ambient, "file2")` and
`operation(#ambient, #read)`, the rule application of `caveat1` would see
`resource(#ambient, "file2"), operation(#ambient, #read), right(#authority, "file2", #read)`
with `X = "file2"`, so it would succeed, but `caveat2` would fail
because it expects `resource(#ambient, "file1")`.

If the verifier provided the facts `resource(#ambient, "file1")` and
`operation(#ambient, #read)`, both caveats would succeed.

#### Broad authority rules

In this example, we have a token with very large rights, that will be attenuated
before giving to a user. The authority block can define rules that will generate
facts depending on ambient data. This helps reduce the size of the token.

```
authority_rules = [
  // if there is an ambient resource and we own it, we can read it
  right(#authority, $0, #read) <- resource(#ambient, $0), owner(#ambient, $1, $0),
  // if there is an ambient resource and we own it, we can write to it
  right(#authority, $0, #write) <- resource(#ambient, $0), owner(#ambient, $1, $0)
]
----------
caveats = [caveat() <- right(#authority, $0, $1), resource(#ambient, $0), operation(#ambient, $1)]
----------
caveats = [caveat() <- resource(#ambient, $0), owner(#alice, $0)] // defines a token only usable by alice
```

These rules will define authority facts depending on ambient data.
If we had the ambient facts `resource(#ambient, "file1")` and
`owner(#ambient, #alice, "file1")`, the authority rules will define
`right(#authority, "file1", #read)` and `right(#authority, "file1", #write)`,
which will allow caveat 1 and caveat 2 to succeed.

If the owner ambient fact does not match the restriction in `caveat2`, the token
check will fail.

#### Expressions

We can define queries or rules with expressions on some predicate values, and
restrict usage based on ambient values:

```
authority=[right(#authority, "/folder/file1", #read),
  right(#authority, "/folder/file2", #read), right(#authority, "/folder2/file3", #read)]
----------
caveats = [caveat() <- resource(#ambient, $0), right(#authority, $0, $1)]
----------
caveats = [caveat() <- time(#ambient, $0), $0 < 2019-02-05T23:00:00Z] // expiration date
----------
caveats = [caveat() <- source_IP(#ambient, $0), $0 in ["1.2.3.4", "5.6.7.8"]] // set membership
----------
caveats = [caveat() <- resource(#ambient, $0), prefix($0, "/folder/")] // prefix operation on strings
```

### Verifier

The verifier provides information on the operation, such as the type of access
("read", "write", etc), the resource accessed, and more ambient data like the
current time, source IP address, revocation lists.
The verifier can also provide its own caveats.

#### Deserializing the token

The token must first be deserialized according to the protobuf format definition,
of either a `Biscuit` or `SealedBiscuit`.
The cryptographic signature must be checked immediately after deserializing. For the
`Biscuit` with a public key signature, the verifier must check that the public key of the
authority block is the root public key it is expecting.
TODO: describe `Biscuit` crypto deserialize process

The blocks can then be deserialized from the `authority` and `blocks` fields.

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

From there, the verifier can start loading ambient data. First, each block contains a `context`
field that can give some information on the verifier to know which data to load (to avoid
loading all of the users, groups, resources, etc). This field is a text field with no restriction
on its format.
The verifier then adds facts and rules obtained from looking up the context, and provides
facts and rules with the `ambient` tag to describe the request.

To check caveats, the verifier will:
- run the Datalog engine ont he facts and rules that were loaded
- create an error list
- for each verifier caveat (caveat provided on the verifier side), check the caveat. If it fails,
add an error to the error list
- for each block:
  - for each caveat, check the caveat. If it fails, add an error to the error list
- if the error list is empty, verification succeeded, if it is not, return the error list

#### Queries

The verifier can also run queries over the loaded data. A query is a datalog rule,
and the query's result are the produced facts.

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
  repeated Fact   facts = 3;
  repeated Rule   rules = 4;
  repeated Rule   caveats = 5;
  optional string context = 6;
}
```

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
order group, that is designed to prevent some implementation mistakes.

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

The signature is `([A], z)`

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

To reduce token size and improve performance, Biscuit uses a symbol table,
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

ProtoBuf: https://developers.google.com/protocol-buffers/
DATALOG: "Datalog with Constraints: A Foundation for
Trust Management Languages" https://www.cs.purdue.edu/homes/ninghui/papers/cdatalog_padl03.pdf
MACAROONS: "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud" https://ai.google/research/pubs/pub41892
Aggregated Gamma Signatures: "Aggregation of Gamma-Signatures and Applications to Bitcoin, Yunlei Zhao" https://eprint.iacr.org/2018/414.pdf
Ristretto: "Ristretto: prime order elliptic curve groups with non-malleable encodings" https://ristretto.group

