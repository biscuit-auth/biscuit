# Biscuit Authentication

## Introduction

## Inspiration

This system draws ideas from X509 certificates,
JWT, macaroons and vanadium.

# Goals and prior art

distributed authorization is traditionally done through
centralized systems like OAuth, where any new authorization
will be delivered by a server, and validated by that same server.
This is fine when working with a monolithic system, or a small
set of microservices.
A request coming from a user agent could result in hundreds of
internal requests between microservices, each requiring a verification
of authorization.

JSON Web Tokens were designed in part to handle distributed authorization,
and in part to provide a stateless authentication token.
While it has been shown that state management cannot be avoid (it is
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


Here is what we want:
- distributed authorization: any node could validate the token only with public information
- delegation: a new, valid token can be created from another one by attenuating its rights
- avoiding identity and impersonation: in a distributed system, not all services
need to know about the token holder's identity. Instead, they care about
specific authorizations
- capabilities: a request carries a token that contains a set of rights
that will be used for authorization, instead of deploying ACLs on every node

## Format

A biscuit token is an ordered list of key and value tuples, stored in HPACK
format. HPACK was chosen to avoid specifying yet another serialization format,
and reusing its data compression features to make tokens small enough to
fit in a cookie.

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

Example:

[
issuer = Clever Cloud
user = user_id_123
rights = clevercloud{-/.*prod/ : *(*) +/org_456-*/: *(*)  +lapin-prod:log(r) +sozu-prod:metric(r)}
]
<signature = base_64(64 bytes signature)>

This token was issued by "Clever Cloud" for user "user_id_123".
It defines the following capabilities, applied in order:
- remove all rights from any tag with the "prod" suffix
- give all rights on any tag that has the "org_456" prefix (even those with "prod" suffix)
- add on the "lapin-prod" tag the "log" feature with right "r"
- add on the "sozu-prod" tag the "metric" feature with right "r"

Example of attenuated token:

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

This new token starts from the same rights as the previous one, but attenuates it
that way:
- all access to tags with "org_456-" prefix is removed
- except that "org_456-test" tag, on which we activate the "database" feature with all accesses

The new token has a signature derived from the previous one and the second block.

## Common keys and values

Key-value tuples can contain arbitrary data, but some of them have predefined
semantics (and could be part of HPACK's static tables to reduce the size of
the token):
- issuer: original creator of the token (validators will be able 
## Cryptography

ISSUER = $issuer_token$
// think about repudation
USER = $user_id$ // using f for field
rights = +/-(tagregexp):feature_name(options),feature_name(options,options) -tag:feature(w)
rights = 

log(r)
log_drain(r,w)
apps(r,w)
metric(r)
domain

/.+/ = *

+/.+/:/.+/(/.+/) -/.*prod/:/.+/(/.+/)
+*:*(*)

clevercloud{  }
//
alias * = /.+/ 



*{-*:*(*)}
clevercloud{+sozu:metric(r) +/.*rust/:/.+/(/.+/) -/.*prod/:/.+/(/.+/) +lapin:log(r)}

# Pairing based cryptography

https://en.wikipedia.org/wiki/Pairing-based_cryptography
Pairing e: G1 x G2 -> Gt with G1 and G2 two additive cyclic groups of prime order q, Gt a multiplicative cyclic group of order q
with a, b from Fq* finite field of order q
with P from G1, Q from G2
e(aP, bQ) == e(P, Q)^(ab)
e != 1

# more specifically:
e(aP, Q) == e(P, aQ) == e(P,Q)^a
e(P1 + P2, Q) == e(P1, Q) * e(P2, Q)

# Signature
choose k from Fq* as private key, g2 a generator of G2
public key P = k*g2

Signature S = k*H1(message) with H1 function to hash message to G1
Verifying: knowing message, P and S
e(S, g2) == e( k*H1(message), g2)
              == e( H1(message), k*g2)
              == e( H1(message), P)

# Signature aggregation
knowing messages m1 and m2, public keys P1 and P2
signatures S1 = Sign(k1, m1), S2  = Sign(k2, m2)
the aggregated signature S = S1 + S2

Verifying:
e(S, g2) == e(S1+S2, g2)
              == e(S1, g2)*e(S2, g2)
              == e(k1*H1(m1), g2) * e(k2*HA(m2), g2)
              == e(H1(m1), k1*g2) * e(H1(m2), k2*g2)
              == e(H1(m1), P1) * e(H1(m2), P2)
so we calculate signature verification pairing for every caveat
then we multiply the result and check equality

we use curve BLS12-381 (Boneh Lynn Shacham) for security reasons
(cf https://github.com/zcash/zcash/issues/2502
for comparions with Barreto Naehrig curves)
assumes computational Diffe Hellman is hard

Example of library this can be implemented with:
- pairing crate: https://github.com/zkcrypto/pairing
- mcl: https://github.com/herumi/mcl
