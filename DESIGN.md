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

Caveats describe which operations are authorized by providing predicates over
the operation's attributes.

Attributes are data, associated with the operation,
that is known when the policy is evaluated, such as an identifier for the
ressource being accessed, the type of the operation (read, write, append, ...),
the operation's parameters (if any), the client's IP address or a
channel-binding value (like the TLS transcript hash).

Available attributes, and their type, are known ahead of time by the verifier.
Some of those attributes are *critical*, and all caveats must provide a *bound*
for each critical attribute.

Bounds are a subset of predicates, that only allow the following:
- `any`: all values match;
- `in <subset>`: only elements in `subset` match; this can be an explicit
  enumeration, or a (non-infinite) range in the case of numeric types.


### Rationale

Some attributes grant authority (such as ressource identifiers, operation type,
...), and failing to include a caveat limiting acceptable values is a common
failure with Macaroons, resulting in authority being accidentally granted.

By marking them critical, two things are achieved:
- They must be bound by caveats, preventing accidental authority grants when new
  values are added.
- Their presence is required in all caveats for a biscuit to be valid; as such:
  - if developers accidentally fail to provide a bound, the biscuit is invalid;
  - biscuits issued before the attribute was defined are implicitely revoked.

For example, consider a data store, which initially only provides read access.
Assume I was granted a biscuit for ressources in it, before a developper
implemented read-write access, along with a `type` attribute (which can be
`Read` or `Write`).  My biscuit suddenly grants me read-write access.

Marking the `type` attribute as critical means that I must request a new
biscuit, that properly specifies whether my access is read and/or write.

Now, if I was to be issued a biscuit with the caveat `type != Write`, before the
types `Append`, `Create`, and `Delete` were added, my the biscuit would again go
from granting read-only access to granting write access; this is why critical
attributes must use bounds.


By requiring that all caveats provide a bound for each critical attribute, we
can guarantee that a biscuit does not gain unintended authority when new
attributes, or new values for them, are added in the system.  (The use of `any`
is considered intentional.)


### Interpretation

Given an operation's `attributes`, the set of `critical` attributes, a given
`biscuit` is evaluated as follows:

```python3
for caveat in biscuit:
  bounds = set()
  for predicate in caveat:
    if not predicate.eval(attributes):
      return False
    if predicate.isbound:
      bounds.add(predicate.attribute)

  if not bounds.contains(critical):
    return False

return True
```


## Format

XXXTODO: Update for caveats

A biscuit token is an ordered list of key and value tuples, stored in HPACK
format. HPACK was chosen to avoid specifying yet another serialization format,
and reusing its data compression features to make tokens small enough to
fit in a cookie.

```
biscuit := block\*, signature
block := HPACK{ kv\* }
kv := ["rights", rights] | ["pub", pubkey] | [TEXT, TEXT]
TEXT := characters (UTF-8 or ASCII?)
pubkey := base64(public key)
rights := namespace { right,\* }
namespace := TEXT
right := (+|-) tag : feature(options)
tag := TEXT | /regexp/ | *
feature := TEXT | /regexp/ | *
options := (r|w|e),\*
```

Example:

```
[
issuer = Clever Cloud
user = user_id_123
rights = clevercloud{-/.*prod/ : *(*) +/org_456-*/: *(*)  +lapin-prod:log(r) +sozu-prod:metric(r)}
]
<signature = base_64(64 bytes signature)>
```

This token was issued by "Clever Cloud" for user "user_id_123".
It defines the following capabilities, applied in order:
- remove all rights from any tag with the "prod" suffix
- give all rights on any tag that has the "org_456" prefix (even those with "prod" suffix)
- add on the "lapin-prod" tag the "log" feature with right "r"
- add on the "sozu-prod" tag the "metric" feature with right "r"

Example of attenuated token:

```
[
issuer = Clever Cloud
user = user_id_123
organization = org_456
rights = clevercloud{-/.*prod/ : *(*) +/org_456-*/: *(*)  +lapin-prod:log(r) +sozu-prod:metric(r)}
]
[
pub = base64(128 bytes key)
rights = clevercloud { -/org_456-*/: *(*) +/org_456-test/ database(*) }
]
<signature = base_64(new 64 bytes signature)>
```

This new token starts from the same rights as the previous one, but attenuates it
that way:
- all access to tags with "org_456-" prefix is removed
- except that "org_456-test" tag, on which we activate the "database" feature with all accesses

The new token has a signature derived from the previous one and the second block.

### Common keys and values

Key-value tuples can contain arbitrary data, but some of them have predefined
semantics (and could be part of HPACK's static tables to reduce the size of
the token):
- issuer: original creator of the token (validators are able to look up the root public key from the issuer field). Appears in the first block
- holder: current holder of the token (will be used for audit purpose). Can appear once per block
- pub: public key used to sign the current block. Appears in every block except the first
- created-on: creation date, in ISO 8601 format. Can appear once per block
- expires-on: expiration date, in ISO 8601 format. Can appear once per block. Must be lower than the expiration dates from previous blocks if present
- restricts: comma separated list of public keys. Any future block can only be signed by one of those keys
- sealed: if present, stops delegation (no further block can be added). Its only value is "true"
- rights: string specifying the rights restriction for this block

Those common keys and values will be present in the HPACK static table


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
- k = ECVRF_nonce(pk, h)
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
- `k = ECVRF_nonce(pk, h)`
- `c = ECVRF_hash_points(h, gamma, g^k, h^k)`
- `s = k + c * sk mod q`
- `W = 1`
- `S = s`
- `PI_0 = (gamma, c, S, W)`

Block n+1: Sign( pk_(n+1), sk_(n+1), message_(n+1), PI_n):
- `([gamma_i], [c_i], S_n, W_n) = PI_n`
- `h_(n+1) = ECVRF_hash_to_curve(pk_(n+1), message_(n+1))`
- `gamma_(n+1) = h_(n+1)^sk_(n+1)`
- choose a random integer nonce k_(n+1) from [0, q-1]
```
c_(n+1) = ECVRF_hash_points(g, h_(n+1), pk_0 * .. * pk_(n+1) ,
    gamma_0 * .. * gamma_(n+1), g^(k_0 + .. + k_(n+1)),
    h^(k_0 + .. + k_(n+1)))
```
- `s_(n+1) = k_(n+1) - c_(n+1) * sk_(n+1) mod q`
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

Note: we could probably store the product of gamma points instead
of the list. This would avoid some calculations and make signatures
smaller

### Gamma signatures

proposed by @bascule

Yao, A. C.-C., & Yunlei Zhao. (2013). Online/Offline Signatures for Low-Power Devices. IEEE Transactions on Information Forensics and Security, 8(2), 283–294.
Aggregation of Gamma-Signatures and Applications to Bitcoin, Yunlei Zhao https://eprint.iacr.org/2018/414.pdf

### BIP32 derived keys

proposed by @bascule
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

