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
`Pr(r0, r1, ..., rk) <- P0(t1_1, t1_2, ..., t1_m1), ..., Pn(tn_1, tn_2, ..., tn_mn), C0(v0), ..., Cx(vx)`.
The part of the left of the arrow is called the *head* and on the right, the *body*.
In a *rule*, each of the `ri` or `ti_j` terms can be of any type. A *rule* is safe
if all of the variables in the head appear somewhere in the body.
We also define a *constraint* `Cx` over the variable `vx`. *Constraints* define
a check of a variable's value when applying the *rule*. If the *constraint* returns
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

A *symbol* indicates a value that supports equality, set inclusion and set exclusion constraints.
Its internal representation has no specific meaning.

An *integer* is a signed 64 bits integer. It supports the following constraints: lower, larger,
lower or equal, larger or equal, equal, set inclusion and set exclusion.

A *string* is a suite of UTF-8 characters. It supports the following constraints: prefix, suffix,
equal, set inclusion, set exclusion, regular expression.

A *byte array* is a suite of bytes. It supports the following constraints: equal, set inclusion,
set exclusion.

A *date* is a 64 bit unsigned integer representing a TAI64. It supports the following constraints:
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

##### Constraints

We can define queries or rules with constraints on some predicate values, and restrict usage
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
  constraints: [Constraint],
}
```

any `Variable` appearing in the  `head` of a `Rule` must also appear
in one of the predicates of its `body`

Constraints express some restrictions on the rules, without having to
implement negation in the datalog engine.

```
Constraint {
  id: u32,
  kind: ConstraintKind,
}

ConstraintKind = IntConstraint | StrConstraint | DateConstraint | SymbolConstraint
```

The `id` field of a constraint must match a `Variable` in the rule.

Integer constraints can have the following values:

```
IntConstraint = Lower | Larger | LowerOrEqual | LargerOrEqual | Equal | In | NotIn

Lower {
  bound: i64
}

Larger {
  bound: i64
}

LowerOrEqual {
  bound: i64
}

LargerOrEqual {
  bound: i64
}

Equal {
  bound: i64
}

In {
  set: [i64]
}

NotIn {
  set: [i64]
}
```

The `set` parameter of `In` and `NotIn` constraints is an array of unique values.

String constraints:

```
StrConstraint = Prefix | Suffix | Equal | In | NotIn | Regex

Prefix {
  bound: string
}

Suffix {
  bound: string
}

Equal {
  bound: string
}

In {
  set: [string]
}

NotIn {
  set: [string]
}

Regex {
  bound: string
}
```

Bytes constraints:

```
BytesConstraint = Equal | In | NotIn

Equal {
  bound: string
}

In {
  set: [string]
}

NotIn {
  set: [string]
}
```

Date constraints:

```
DateConstraint = Before | After

Before {
  bound: date
}

After {
  bound: date
}
```

Symbol constraints:

```
StrConstraint = In | NotIn

In {
  set: [Symbol]
}

NotIn {
  set: [Symbol]
}
```

#### Adding a new block

A new block will have an index that increments on the last block's index.
It reuses the token's symbol table. If new symbols must be added to the
table when adding facts and rules, the new block will only hold the new
symbols.
When serializing the new token, the new block must first be serialized
to a byte array via Protobuf encoding. Then a new aggregated signature is created
from the previous blocks, the previous aggregated signature and the
new key pair for this block. The new serialized token will have the same
authority block as the previous one, its blocks field will have the previous
one's blocks with the new block appended, and the new signature.

## Cryptography

This design requires a non interactive signature aggregation scheme.
We have multiple propositions, described in annex to the document.
We have not chosen yet which scheme will be used. The choice will
depend on the speed on the algorithm (for signature, aggregation and
verification), the size of the keys and signatures, and pending
an audit.

The system needs to be non interactive, so that delegation can
be done "offline", without talking to the initial authorization
system, or any of the other participants in the delegation chain.

A signature aggregation scheme, can take a list of tuples
(message, signature, public key), and produce one signature
that can be verified with the list of messages and public keys.
An additional important property we need here: we cannot get
the original signatures from an aggregated one.

### Biscuit signature scheme

Assuming we have the following primitives:

- `Keygen()` can give use a publick key `pk` and a private key `sk`
- `Sign(sk, message)` can give us a signature `S`, with `message` a byte array or arbitrary length
- `Aggregate(S1, S2)` can give us an aggregated signature `S`. Additionally, `Aggregate`
can be called with an aggregated signature `S` and a single signature `S'`, and return a new
aggregated signature `S"`
- `Verify([message], [pk], S)` will return true if the signature `S`
is valid for the list of messages `[message]` and the list of public keys `[pk]`

#### First layer of the authorization token

The issuing server performs the following steps:

- `(pk1, sk1) <- Keygen()` (done once)
- create the first block (we can omit `pk1` from that block, since we assume the
token will be verified on a system that knows that public key)
- Serialize that first block to `m1`
- `S <- Sign(sk1, m1)`
- `token1 <- m1||S`

#### Adding a block to the token

The holder of a token can attenuate it by adding a new block and
signing it, with the following steps:

- With `token1` containing `[messages]||S`, and a way to get
the list of public keys `[pk]` for each block from the blocks, or
from the environment
- `(pk2, sk2) <- Keygen()`
- With `message2` the block we want to add (containing `pk2`, so it
can be found in further verifications)`
- `S2 <- Sign(sk2, message2)`
- `S' <- Aggregate(S, S2)`
- `token2 <- [messages]||message2||S'`

Note: the block can contain `sealed: true` in its keys and values, to
indicate a token should not be attenuated further.

Question: should the previous signature be verified before adding the
new block?

#### Verifying the token

- With `token` containing `[messages]||S`
- extract `[pk]` from `[messages]` and the environment: the first public
key should already be known, and for performance reasons, some public keys
could also be present in the list of common keys and values
- `b <- Verify([messages], [pk], S)`
- if `b` is true, the signature is valid
- proceed to validating rights

### Sealed Biscuit scheme

In some cases, we might want to convert the token to a symmetric key based
token that cannot be attenuated further. Common use case: contact the verifier
once, the verifier checks the signature, and generates from it a short lived
token with the same authorization, but that can be checked much faster than
public key based tokens.

TODO: specify an AEAD scheme that would be usable for this

## Annex 1: Cryptographic design proposals

### Pairing based cryptography

proposed by @geal

Assuming we have a pairing e: G1 x G2 -> Gt with G1 and G2 two additive cyclic groups of prime order q, Gt a multiplicative cyclic group of order q
with a, b from Fq* finite field of order q
with P from G1, Q from G2

We have the following properties:
- `e(aP, bQ) == e(P, Q)^(ab)`
- `e != 1`

More specifically:

- `e(aP, Q) == e(P, aQ) == e(P,Q)^a`
- `e(P1 + P2, Q) == e(P1, Q) * e(P2, Q)`

#### Signature

- choose k from Fq* as private key, g2 a generator of G2
- public key P = k*g2

- Signature S = k*H1(message) with H1 function to hash message to G1
- Verifying: knowing message, P and S
```
e(S, g2) == e( k*H1(message), g2)
         == e( H1(message), k*g2)
         == e( H1(message), P)
```

#### Signature aggregation

- knowing messages m1 and m2, public keys P1 and P2
- signatures S1 = Sign(k1, m1), S2 = Sign(k2, m2)
- the aggregated signature S = S1 + S2

Verifying:
```
e(S, g2) == e(S1+S2, g2)
         == e(S1, g2)*e(S2, g2)
         == e(k1*H1(m1), g2) * e(k2*HA(m2), g2)
         == e(H1(m1), k1*g2) * e(H1(m2), k2*g2)
         == e(H1(m1), P1) * e(H1(m2), P2)
```

so we calculate signature verification pairing for every caveat
then we multiply the result and check equality

we use curve BLS12-381 (Boneh Lynn Shacham) for security reasons
(cf https://github.com/zcash/zcash/issues/2502
for comparions with Barreto Naehrig curves)
assumes computational Diffe Hellman is hard

Performance is not stellar (with the pairing crate, we can
spend 30ms verifying a token with 3 blocks, with mcl 1.7ms).

Example of library this can be implemented with:
- pairing crate: https://github.com/zkcrypto/pairing
- mcl: https://github.com/herumi/mcl

### Elliptic curve verifiable random functions

proposed by @KellerFuchs

https://tools.ietf.org/html/draft-irtf-cfrg-vrf-04

Using the primitives defined in https://tools.ietf.org/html/draft-irtf-cfrg-vrf-04#section-5 :

```
F - finite field
2n - length, in octets, of a field element in F
E - elliptic curve (EC) defined over F
m - length, in octets, of an EC point encoded as an octet string
G - subgroup of E of large prime order
q - prime order of group G
cofactor - number of points on E divided by q
g - generator of group G
Hash - cryptographic hash function
hLen - output length in octets of Hash
```

Constraints on options:

Field elements in F have bit lengths divisible by 16

hLen is equal to 2n

Steps:

Keygen:
`(pk, sk) <- Keygen()`: sk random x with 0 < x < q

#### Basic EC-VRF behaviour

Sign(pk, sk, message):

creating a proof pi = ECVRF_prove(pk, sk, message):

- h = ECVRF_hash_to_curve(pk, message)
- gamma = h^sk
- k = ECVRF_nonce(sk, h)
- c = ECVRF_hash_points(h, gamma, g^k, h^k)
- s = k + c * sk mod q
- pi = (gamma, c, s)

Verify(pk, pi, message) for one message and its signature:

- (gamma, c, s) = pi
```
u = pk^-c * g^s
  = g^(sk*-c)*g^(k + c*sk)
  = g^k
```
- h = ECVRF_hash_to_curve(pk, message)
```
v = gamma^-c * h^s
  = h^(sk*-c)*h^(k + c*sk)
  = h^k
```
- c' = ECVRF_hash_points(h, gamma, u, v)
- return c == c'

#### Aggregating signatures

Sign:

First block: Sign0(pk, sk, message)
- `h = ECVRF_hash_to_curve(pk, message)`
- `gamma = h^sk`
- `k = ECVRF_nonce(sk, h)`
- `c = ECVRF_hash_points(h, gamma, g^k, h^k)`
- `s = k + c * sk mod q`
- `W = 1`
- `S = s`
- `PI_0 = ([gamma], [c], S, W)`

Block n+1: Sign( pk_(n+1), sk_(n+1), message_(n+1), PI_n):
- `([gamma_i], [c_i], S_n, W_n) = PI_n`
- `h_(n+1) = ECVRF_hash_to_curve(pk_(n+1), message_(n+1))`
- `gamma_(n+1) = h_(n+1)^sk_(n+1)`
- `k = ECVRF_nonce(sk, h)`
```
u_n = pk_0^-c_0 * .. * pk_n^-c_n * g^S_n
  = g^(sk_0*-c_0) * .. * g^(sk_n*-c_n) * g^(k_0 + sk0*c_0 + .. + k_n + sk_n*c_n)
  = g^(k_0 + .. + k_n)

v_n = W* gamma_0^-c_0 * h_0^S * .. * gamma_n^-c_n * h_n^S
  = h_0^(s_0 - S) * .. * h_n^(s_0 - S) * h_0^(sk_0*-c_0 + S) * .. * h_n^(sk_n*-c_n + S)
  = h_0^(k_0 + sk_0*c_0 - S - sk_0*c_0 + S) * .. * h_n^(k_n + sk_n*c_n - S - sk_n*c_n + S)
  = h_0^k_0 * .. * h_n^k_n
```

```
c_(n+1) = ECVRF_hash_points(g, h_(n+1), pk_0 * .. * pk_(n+1) ,
    gamma_0 * .. * gamma_(n+1), u_n * g^k_(n+1), v_n * h_(n+1)^k_(n+1))
```
- `s_(n+1) = k_(n+1) + c_(n+1) * sk_(n+1) mod q`
- `S_(n+1) = S_n + s_(n+1)`
- `W_(n+1) = W_n * (h_0 * .. * h_n)^(-s_(n+1)) * h_(n+1)^(-Sn) == h_0^(s_0 - S_(n+1)) * .. * h_(n+1)^(s_(n+1) - S_(n+1))`
- `PI_(n+1) = ([gamma_i], [c_i], S_(n+1), W_(n+1))`

Verify([pk], PI, [message]) (with n blocks):


Aggregate(pk', pi', [pk], PI) with [pk] list of public keys and PI aggregated signature:
- `([gamma], [c], S, W, C) = PI`
- check that `n = |[pk]| == |[message]| == |[gamma]| == |[c]|`
```
U = pk_0^-c_0 * .. * pk_n^-c_n * g^S
  = g^(sk_0*-c_0) * .. * g^(sk_n*-c_n) * g^(k_0 + sk0*c_0 + .. + k_n + sk_n*c_n)
  = g^(k_0 + .. + k_n)
```

```
V = W* gamma_0^-c_0 * h_0^S * .. * gamma_n^-c_n * h_n^S
  = h_0^(s_0 - S) * .. * h_n^(s_0 - S) * h_0^(sk_0*-c_0 + S) * .. * h_n^(sk_n*-c_n + S)
  = h_0^(k_0 + sk_0*c_0 - S - sk_0*c_0 + S) * .. * h_n^(k_n + sk_n*c_n - S - sk_n*c_n + S)
  = h_0^k_0 * .. * h_n^k_n
```
- `C = ECVRF_hash_points(h_n, gamma_0 * .. * gamma_n, U, V)`
- verify that `C == c_n`

### Elliptic curve verifiable random functions: second method

This is a variant of the previous scheme, for which the product of
gamma points is precalculated, so that we do not need to do it to
aggregate a new signature or verify it. This also reduces the size
of the signature.

Same primitives as before:

```
F - finite field
2n - length, in octets, of a field element in F
E - elliptic curve (EC) defined over F
m - length, in octets, of an EC point encoded as an octet string
G - subgroup of E of large prime order
q - prime order of group G
cofactor - number of points on E divided by q
g - generator of group G
Hash - cryptographic hash function
hLen - output length in octets of Hash
```

Constraints on options:

Field elements in F have bit lengths divisible by 16

hLen is equal to 2n

Steps:

Keygen:
`(pk, sk) <- Keygen()`: sk random x with 0 < x < q

#### Aggregating signatures

Sign:

First block: Sign0(pk, sk, message)
- `h = ECVRF_hash_to_curve(pk, message)`
- `gamma = h^sk`
- `k = ECVRF_nonce(sk, h)`
- `c = ECVRF_hash_points(h, pk, g^k, h^k)`
- `s = k + c * sk mod q`
- `W = 1`
- `S = s`
- `PI_0 = (-c * gamma, [c], S, W)`

Block n+1: Sign( pk_(n+1), sk_(n+1), message_(n+1), PI_n):
- `(gamma_agg, [c_i], S_n, W_n) = PI_n`
- `h_(n+1) = ECVRF_hash_to_curve(pk_(n+1), message_(n+1))`
- `gamma_(n+1) = h_(n+1)^sk_(n+1)`
- `k = ECVRF_nonce(sk, h)`
```
u_n = pk_0^-c_0 * .. * pk_n^-c_n * g^S
  = g^(sk_0*-c_0) * .. * g^(sk_n*-c_n) * g^(k_0 + sk0*c_0 + .. + k_n + sk_n*c_n)
  = g^(k_0 + .. + k_n)
```

```
v_n = W * gamma_agg * h_0^S * ... * h_n^S
    = W * gamma_0^-c_0 * h_0^S * .. * gamma_n^-c_n * h_n^S
    = h_0^(s_0 - S) * .. * h_n^(s_0 - S) * h_0^(sk_0*-c_0 + S) * .. * h_n^(sk_n*-c_n + S)
    = h_0^(k_0 + sk_0*c_0 - S - sk_0*c_0 + S) * .. * h_n^(k_n + sk_n*c_n - S - sk_n*c_n + S)
    = h_0^k_0 * .. * h_n^k_n
```
```
c_(n+1) = ECVRF_hash_points(g, h_(n+1), pk_0 * .. * pk_(n+1) ,
    u_n * g^k, v_n * h^k)
```
- `s_(n+1) = k_(n+1) - c_(n+1) * sk_(n+1) mod q`
- `S_(n+1) = S_n + s_(n+1)`
- `W_(n+1) = W_n * (h_0 * .. * h_n)^(-s_(n+1)) * h_(n+1)^(-Sn) == h_0^(s_0 - S_(n+1)) * .. * h_(n+1)^(s_(n+1) - S_(n+1))`
- `PI_(n+1) = (gamma_agg * (-c_(n+1) * gamma_(n+1)), [c_i], S_(n+1), W_(n+1))`


Verify([pk], PI, [message]) (with n blocks):


Aggregate(pk', pi', [pk], PI) with [pk] list of public keys and PI aggregated signature:
- `([gamma], [c], S, W, C) = PI`
- check that `n = |[pk]| == |[message]| == |[gamma]| == |[c]|`
```
u = pk_0^-c_0 * .. * pk_n^-c_n * g^S
  = g^(sk_0*-c_0) * .. * g^(sk_n*-c_n) * g^(k_0 + sk0*c_0 + .. + k_n + sk_n*c_n)
  = g^(k_0 + .. + k_n)
```

```
v = W * gamma_agg * h_0^S * ... * h_n^S
  = W * gamma_0^-c_0 * h_0^S * .. * gamma_n^-c_n * h_n^S
  = h_0^(s_0 - S) * .. * h_n^(s_0 - S) * h_0^(sk_0*-c_0 + S) * .. * h_n^(sk_n*-c_n + S)
  = h_0^(k_0 + sk_0*c_0 - S - sk_0*c_0 + S) * .. * h_n^(k_n + sk_n*c_n - S - sk_n*c_n + S)
  = h_0^k_0 * .. * h_n^k_n
```
- `C = ECVRF_hash_points(h_n, pk_0 * ... pk_n, U, V)`
- verify that `C == c_n`

### Challenge tokens

Another method based on a more classical PKI, where the token contains
the secret key of the last caveat. To send the token for verification,
that key is used to sign the token with a nonce and current time, to
prove that we own it. We send the token without the key, but with the
signature. The verification token cannot be further attenuated.

Here's a description of the scheme:

```
(pk1, sk1) = keygen()
(pk2, sk2) = keygen()
s1 = sign(sk1, caveat1+pk2)
token1=caveat1+pk2+s1+sk2
```

Minting a new token
```
(pk3, sk3) = keygen()
s2 = sign(sk2, caveat2+pk3)
token2=caveat1+pk2+s1+caveat2+pk3+s2+sk3
```

Sending token2 for verification:
```
verif_token2=caveat1+pk2+s1+caveat2+pk3+s2
h = sign(sk3, nonce+time+verif_token2)
sending verif_token2+h
```

The verifier knows pk1 and can check the chain, and h allows checking that we hold sk3

### Gamma signatures

proposed by @tarcieri

Yao, A. C.-C., & Yunlei Zhao. (2013). Online/Offline Signatures for Low-Power Devices. IEEE Transactions on Information Forensics and Security, 8(2), 283–294.
Aggregation of Gamma-Signatures and Applications to Bitcoin, Yunlei Zhao https://eprint.iacr.org/2018/414.pdf

### BIP32 derived keys

proposed by @tarcieri
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

