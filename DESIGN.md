**note: this is the initial design document of Biscuit, explaining the project's
intentions and the solutions that were evaluated. It is not up to date with the
current format of the token.
For a complete description of the current format, see SPECIFICATIONS.md. For a
usage explanation, see SUMMARY.md**

# Biscuit Authentication

## Introduction

Distributed authorization is traditionally done through
centralized systems like OAuth, where any new authorization
will be delivered by a server, and validated by that same server.
This is fine when working with a monolithic system, or a small
set of microservices.

However, in microservice architectures, a single request coming from a user
agent could result in hundreds of internal requests between microservices, each
requiring a verification of authorization, making it inpractical to delegate
it to a centralized server.

### Inspiration

This system draws ideas from X509 certificates, JWT, Macaroons and Vanadium.

JSON Web Tokens were designed in part to handle distributed authorization,
and in part to provide a stateless authentication token.
While it has been shown that state management cannot be avoided (it is
the only way to have correct revocation), distributed authorization
has proven useful. JSON Web Tokens are JSON objects that carry
data about their principal, expiration dates and a serie of claims,
all signed by the authorization server's public key. Any service that
knows and trusts that public key will be able to validate the token.
JWTs are also quite large and often cannot fit in a cookie, so they are
often stored in localstorage, where they are easily stolen via XSS.

Macaroons provide a token that can be delegated: the holder can
create a new, valid token from the first one, by attenuating its
rights. They are built from a secret known to the authorization server.
A token can be created from a caveat and the HMAC of the secret and the caveat.
To build a new token, we add a caveat, remove the previous HMAC signature,
and add a HMAC of the previous signature and the new caveat (so from
an attenuated token we cannot go back to a more general one).
This allows use to build tokens with very limited access, that wan can hand
over to an external service, or build unique restricted tokens per requests.
Building macaroons on a secret means that any service that wants to validate
the token must know that secret.

Vanadium builds a distributed authorization and delegation system
based on public keys, by binding a token to a public key with
a certificate, and a blessing (a name with an optional prefix).
Attenuating the token means generating a new blessing by appending
a name, and signing a list of caveats and the public key of the new
holder. The token is then validated first by validating the certificate,
then validating the caveats, then applying ACLs based on patterns
in the blessings.


### Goals

Here is what we want:
- distributed authorization: any node could validate the token only with public information
- delegation: a new, valid token can be created from another one by attenuating its rights
- avoiding identity and impersonation: in a distributed system, not all services
need to know about the token holder's identity. Instead, they care about
specific authorizations
- capabilities: a request carries a token that contains a set of rights
that will be used for authorization, instead of deploying ACLs on every node


## Structure and semantics

A biscuit is structured as a cryptographic, append-only list; its elements are
called *caveats*, and describe authorization properties.  As with Macaroons,
an operation must comply with all caveats in order to be allowed by the biscuit.

Caveats are written as queries defined in a flavor of Datalog that supports
constraints on some data types ( https://www.cs.purdue.edu/homes/ninghui/papers/cdatalog_padl03.pdf ),
without support for negation. This simplifies its implementation and makes
the caveat more precise.

### Terminology

A Biscuit Datalog program contains *facts* and *rules*, which are made of *predicates*
over the following types: *symbol*, *variable*, *integer*, *string*, *byte array* and *date*.
While Biscuit does not use a textual representation for storage, we will use
one for this specification and for pretty printing of caveats.
A *predicate* has the form `Predicate(v0, v1, ..., vn)`.
A *fact* is a *predicate* that does not contain any *variable*.
A *rule* has the form:
`Pr(r0, r1, ..., rk) <- P0(t1_1, t1_2, ..., t1_m1), ..., Pn(tn_1, tn_2, ..., tn_mn), C0(v0, ..., vi), ..., Cx(vx, ..., vy)`.
The part of the left of the arrow is called the *head* and on the right, the *body*.
In a *rule*, each of the `ri` or `ti_j` terms can be of any type. A *rule* is safe
if all of the variables in the head appear somewhere in the body.
We also define an *expression* `Cx` over the variables `vx` to `vy`. *Expressions*
define a check of variable values when applying the *rule*. If the *expression* returns
`false`, the *rule* application fails.
A *query* is a type of *rule* that has no head. It has the following form:
`?- P0(t1_1, t1_2, ..., t1_m1), ..., Pn(tn_1, tn_2, ..., tn_mn), C0(v0), ..., Cx(vx)`.
When applying a *rule*, if there is a combination of *facts* that matches the body's
predicates, we generate a new *fact* corresponding to the head (with the variables
bound to the corresponding values).
We will represent the various types as follows:
- symbol: `#a`
- variable: `v?`
- integer: `12`
- string: `"hello"`
- byte array: `hex:01A2`
- date in RFC 3339 format: `1985-04-12T23:20:50.52Z`

As an example, assuming we have the following facts: `parent(#a, #b)`, `parent(#b, #c)`, `#parent(#c, #d)`.
If we apply the rule `grandparent(x?, z?) <- parent(x?, y?), parent(y? z?)`, we will
try to replace the predicates in the body by matching facts. We will get the following combinations:
- `grandparent(#a, #c) <- parent(#a, #b), parent(#b, #c)`
- `grandparent(#b, #d) <- parent(#b, #c), parent(#c, #d)`

The system will now contain the two new facts `grandparent(#a, #c)` and `grandparent(#b, #d)`.
Whenever we generate new facts, we have to reapply all of the system's rules on the facts,
because some rules might give a new result. Once rules application does not generate any new facts,
we can stop.

### Data types

A *symbol* indicates a value that supports equality, set inclusion and set exclusion checks.
Its internal representation has no specific meaning.

An *integer* is a signed 64 bits integer. It supports the following operations: lower, larger,
lower or equal, larger or equal, equal, set inclusion and set exclusion.

A *string* is a suite of UTF-8 characters. It supports the following operations: prefix, suffix,
equal, set inclusion, set exclusion, regular expression.

A *byte array* is a suite of bytes. It supports the following operations: equal, set inclusion,
set exclusion.

A *date* is a 64 bit unsigned integer representing a TAI64. It supports the following operations:
before, after.

A *boolean* is `true` or `false`.

A *set* is a deduplicated list of terms of the same type. It cannot contain
variables or other sets.

### Usage

A biscuit token defines some scopes for facts and rules. The *authority* scope is defined in the first
block of the token. It provides a set of facts and rules indicating the starting rights of the token.
An *authority* fact will be defined as `predicate(#authority, t0, t1, ..., tn)`. *Authority* facts can
only be defined by *authority* rules.
The *ambient* scope is provided by the verifier. It contains facts corresponding to the query, like
which resource we try to access, with which operation (read, write, etc), the current time, the source IP, etc.
*Ambient* facts can only be defined by the verifier.
The *local* scope contains facts specific to one block of the token. Between each block evaluation,
we do not keep the *local* facts, instead restarting from the *authority* and *ambient* facts.
Each block can contain caveats, which are *queries* that must all succeed for the token to be valid.
Additionally, the verifier can have its own set of queries that must succeed to validate the token.

#### Examples

This first token defines a list of authority facts giving `read` and `write` rights on `file1`, `read`
on `file2`. The first caveat checks that the operation is `read` (and will not allow any other `operation` fact),
and then that we have the `read` right over the resource.
The second caveat checks that the resource is `file1`.

```
authority=[right(#authority, #file1, #read), right(#authority, #file2, #read), right(#authority, #file1, #write)]
----------
caveat1 = resource(#ambient, X?), operation(#ambient, #read), right(#authority, X?, #read)  // restrict to read operations
----------
caveat2 = resource(#ambient, #file1)  // restrict to file1 resource
```

##### broad authority rules

In this example, we have a token with very large rights, that will be attenuated before giving to a user:

```
authority_rules = [
  right(#authority, X?, #read) <- resource(#ambient, X?), owner(#ambient, Y?, X?), // if there is an ambient resource and we own it, we can read it
  right(#authority, X?, #write) <- resource(#ambient, X?), owner(#ambient, Y?, X?) // if there is an ambient resource and we own it, we can write to it
]
----------
caveat1 = right(#authority, X?, Y?), resource(#ambient, X?), operation(#ambient, Y?)
----------
caveat2 = resource(#ambient, X?), owner(#alice, X?) // defines a token only usable by alice
```

These rules will define authority facts depending on ambient data.
If we had the ambient facts `resource(#ambient, #file1)` and `owner(#ambient, #alice, #file1)`,
the authority rules will define `right(#authority, #file1, #read)` and `right(#authority, #file1, #write)`,
which will allow caveat 1 and caveat 2 to succeed.

If the owner ambient fact does not match the restriction in caveat2, the token check will fail.

##### Expressions

We can define queries or rules with expressions on some predicate values, and restrict usage
based on ambient values:

```
authority=[right(#authority, "/folder/file1", #read), right(#authority, "/folder/file2", #read),
  right(#authority, "/folder2/file3", #read)]
----------
caveat1 = resource(#ambient, X?), right(#authority, X?, Y?)
----------
caveat2 = time(#ambient, T?), T? < 2019-02-05T23:00:00Z // expiration date
----------
caveat3 = source_IP(#ambient, X?) | X? in ["1.2.3.4", "5.6.7.8"] // set membership
----------
caveat4 = resource(#ambient, X?) | prefix(X?, "/folder/") // prefix or suffix match
```

## Implementation

A biscuit token has the following operations:
```
Token {
  create(rng: Rng, root: PrivateKey, authority: Block) -> Token
  append(&self, rng: Rng, key: PrivateKey, block: Block) -> Token
  deserialize(data: [u8], root: PublicKey) -> Result<Token, Error>
  deserialize_sealed(data: [u8], secret: SymmetricKey) -> Result<Token, Error>
  serialize(&self) -> [u8]
  serialize_sealed(&self, secret: SymmetricKey) -> [u8]
}

Verifier {
  add_fact(&mut self, fact: Fact)
  add_rule(&mut self, rule: Rule)
  add_caveat(&mut self, caveat: Rule)
  verify(&self, token: Token) -> Result<(), Vec<String>> // errors are aggregated strings indicating which caveats failed
}

Block {
  create(index: u32, base_symbols: SymbolTable) -> Block
  add_symbol(&mut self, s: string) -> Symbol
  add_fact(&mut self, fact: Fact)
  add_rule(&mut self, caveat: Rule)
}
```

### Caveat creation API

Rights and attenuation could be written directly as datalog rules,
but it would be useful to provide a high level API that defines
some usual facts and rules without errors.

```
Token {
  builder() -> BiscuitBuilder
  create_block(&self) -> BlockBuilder
}

BiscuitBuilder {
  create(rng: Rng, root: PrivateKey, base_symbols: SymbolTable) -> Result<Biscuit, Error>
  add_authority_fact(&mut self, fact: Fact)
  add_authority_rule(&mut self, caveat: Rule)
  add_right(&mut self, resource: string, right: string)
}

BlockBuilder {
  create(index: u32, base_symbols: SymbolTable) -> Block
  add_fact(&mut self, fact: Fact)
  add_caveat(&mut self, caveat: Rule)
  check_right(&mut self, right: string)
  resource_prefix(&mut self, prefix: string)
  resource_suffix(&mut self, suffix: string)
  expiration_date(&mut self, expires_on: date)
  revocation_id(&mut self, id: i64)
}
```

- `add_right(&mut self, resource: string, right: string)` will generate the fact: `right(#authority, resource, right)`
- `check_right(&mut self, right: string)` will generate the caveat:
`check_right(X?) <- resource(#ambient, Y?), operation(#ambient, X?), right(#authority, Y?, X?)`
- `resource_prefix(&mut self, prefix: string)` will generate the caveat:
`prefix(X?) <- resource(#ambient, X?) | prefix_constraint(X?, prefix)
- `resource_suffix(&mut self, suffix: string)` will generate the caveat:
`suffix(X?) <- resource(#ambient, X?) | suffix_constraint(X?, prefix)
- `expiration_date(&mut self, expires_on: date)` will generate the caveat:
`expiration(X?) <- time(#ambient, X?) | before_constraint(X?, expires_on)
- `revocation_id(&mut self, id: i64)` will generate the fact: `revocation_id(id)`

```
Verifier {
  resource(&mut self, resource: string)
  operation(&mut self, operation: string)
  time(&mut self)
  revocation_check(&mut self, set: [i64])
  add_rule
  add_caveat
  add_query
}
```

- `resource(&mut self, resource: string)` will generate the fact: `resource(#ambient, resource)`
- `operation(&mut self, operation: string)` will generate the fact: `operation(#ambient, operation)`
- `time(&mut self)` will calculate the current time `now` and generate the fact: `time(#ambient, now)`
- `revocation_check(&mut self, set: [i64])` will add the verifier specific caveat as follows:
`revocation_check(X?) <- revocation_id(X?) | X? not in set`

### Format

A Biscuit token relies on [Protocol Buffers](https://developers.google.com/protocol-buffers/)
encoding as base format. The current version of the schema is in [schema.proto](https://github.com/CleverCloud/biscuit/blob/master/schema.proto)

Basic elements:
- u8: 8 bits unsigned integer
- u32: 32 bits unsigned integer
- `[u8]`: byte array of unspecified length
- `string`: UTF-8 string of unspecified length
- `date`: TAI64 label, as specified in https://cr.yp.to/libtai/tai64.html
- `Symbol`: 64 bits unsigned integer. Index of a string inside the symbol table


Here is the "on the wire" format:

```
Biscuit {
  authority: [u8],
  blocks: [[u8]], // array of byte arrays
  signature: // NOT SPECIFIED, PENDING CHOICE OF CRYPTOGRAPHIC SCHEME
}
```

The `signature` field can contain the aggregated public key signatures
in the case of the main token, or the symmetric signature data, in the
case of the sealed token.
The `signature` applies to the content of the `authority` block, and
the content of each element of `blocks`.

Once the signature is verified, the `authority` and `blocks` elements
can be further deserialized. They represent a `Block` structure in Protobuf
encoding:

```
Block {
  index: u32,
  symbols: SymbolTable,
  facts: [Fact],
  rules: [Rule],
  caveats: [Rule]
}
```

Each `Block` has a unique index field, to check their order of appearance.
The `authority` block always has index 0.
The symbol table contains an array of UTF-8 strings. It indicates a mapping
index -> string to avoid repeating some strings in the token:

```
SymbolTable {
  symbols: [string]
}
```

When deserializing the token, the token's symbol table is created as follows:
- start from the default symbol table, which contains the common symbols:
`authority`, `ambient`, `resource`, `operation`, `right`, `current_time`, `revocation_id`
- append the symbol table of the `authority` block
- append the symbol table of each block of `blocks`, in order

The datalog implementation relies on the `ID` and `Predicate` basic types:

```
ID = Symbol | Variable | Integer | Str | Date
Variable = u32
Integer = i64
Str = string
Bytes = [u8]
Date = date
```

```
Predicate {
  name: Symbol,
  ids: [ID]
}
```

Datalog facts are specified as follows:

```
Fact = Predicate
```

a `Fact` cannot contain a `Variable` `ID`.

Datalog rules are specified as follows:

```
Rule {
  head: Predicate,
  body: [Predicate],
  expressions: [Expression],
}
```

any `Variable` appearing in the  `head` of a `Rule` must also appear
in one of the predicates of its `body`

Expressions express some restrictions on the rules, without having to
implement negation in the datalog engine.

They are encoded as bytecode for a stack machine with unary and binary operations.
For the rule to succeed, an expression must have all of its variables bound to a
value of the expected type (depending on the operations) and it must evaluate to
`true`.

```
Expression {
  ops: [Op],
}

Op = Value | Unary | Binary

Value = ID
Unary = Negate
Binary = LessThan | GreaterThan | LessOrEqual | GreaterOrEqual | Equal | In | NotIn | Prefix | Suffix | Regex | Add | Sub | Mul | Div | And | Or
```

The `id` field of a constraint must match a `Variable` in the rule.

Integer values can be used with the following operations: Negate, Lower, Larger,
LowerOrEqual, LargerOrEqual, Equal, In, NotIn, Add, Sub, Mul, Div

The `set` parameter of `In` and `NotIn` constraints is an array of unique values.

String values can be used with the following operations: Prefix, Suffix, Equl In, NotIn, Regex

Byte array values can be used with the following operations: Equal, In, NotIn

Date values can be used with the following operations: LessOrEqual, GreaterOrEqual

Symbol values can be used with the following operations: In, NotIn

#### Adding a new block

A new block will have an index that increments on the last block's index.
It reuses the token's symbol table. If new symbols must be added to the
table when adding facts and rules, the new block will only hold the new
symbols.
When serializing the new token, the new block must first be serialized
to a byte array via Protobuf encoding. Then a new signature is created
from the previous blocks, and the next key pair is generated. The new
serialized token will have the same authority block as the previous one,
its blocks field will have the previous one's blocks with the new block
appended, and the new signature.

## Cryptography

This design requires a signature scheme that can be extended without
interaction with the origin token creator, so that delegation can
be done "offline", without talking to the initial authorization
system, or any of the other participants in the delegation chain.

### Biscuit signature scheme

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
* `sig_0 = sign(sk_0, data_0 + pk_1)`

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

We generate at random `(pk_n+2, sk_n+2)` and the signature `sig_n+1 = sign(sk_n+1, data_n+1 + pk_n+2)`

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

- verify(pk_i, sig_i, data_i+pk_i+1)

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

