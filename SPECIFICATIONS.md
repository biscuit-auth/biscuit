# Biscuit, a bearer token with offline attenuation and decentralized verification

placeholder: please see [PR 20](https://github.com/CleverCloud/biscuit/pull/20)
for the current version of the specifications with comments.

## Introduction

Biscuit is a bearer token that supports offline attenuation, can be verified
by any system that would hold some public information, and provides a flexible
caveat language based on logic programming. It is serialized as
Concise Binary Object Representation [CBOR], and designed to be small enough
for storage HTTP cookies.

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

Biscuit holds a set of rights, defined in its authority block, and a list of
caveats (restrictions) to those rights or to the accompanying operation, in the form
of logic queries. The holder of a biscuit token can at any time create a new
token by adding more caveats, but they cannot remove existing caveats.

The token is protected by public key cryptography operations: the initial creator
of a token holds a secret key, and any verifier for the token needs only know
the corresponding public key.
Any attenuation operation will employ ephemeral key pairs that are meant to be
destroyed as soon as they are used.

There is also a sealed version of that token that uses symmetric cryptography
to generate a token that cannot be further attenuated, but is faster to verify.

The logic language used to design rights, caveats and operation data is a
variant of datalog that accepts constraints on some data types.

### Examples

#### Basic token

This first token defines a list of authority facts giving `read` and `write`
rights on `file1`, `read` on `file2`. The first caveat checks that the operation
is `read` (and will not allow any other `operation` fact), and then that we have
the `read` right over the resource.
The second caveat checks that the resource is `file1`.

```
authority=[right(#authority, #file1, #read), right(#authority, #file2, #read),
  right(#authority, #file1, #write)]
----------
caveat1 = resource(#ambient, X?), operation(#ambient, #read),
  right(#authority, X?, #read)  // restrict to read operations
----------
caveat2 = resource(#ambient, #file1)  // restrict to file1 resource
```

#### Broad authority rules

In this example, we have a token with very large rights, that will be attenuated
before giving to a user:

```
authority_rules = [
  // if there is an ambient resource and we own it, we can read it
  right(#authority, X?, #read) <- resource(#ambient, X?), owner(#ambient, Y?, X?),
  // if there is an ambient resource and we own it, we can write to it
  right(#authority, X?, #write) <- resource(#ambient, X?), owner(#ambient, Y?, X?)
]
----------
caveat1 = right(#authority, X?, Y?), resource(#ambient, X?), operation(#ambient, Y?)
----------
caveat2 = resource(#ambient, X?), owner(#alice, X?) // defines a token only usable by alice
```

These rules will define authority facts depending on ambient data.
If we had the ambient facts `resource(#ambient, #file1)` and
`owner(#ambient, #alice, #file1)`, the authority rules will define
`right(#authority, #file1, #read)` and `right(#authority, #file1, #write)`,
which will allow caveat 1 and caveat 2 to succeed.

If the owner ambient fact does not match the restriction in caveat2, the token
check will fail.

##### Constraints

We can define queries or rules with constraints on some predicate values, and
restrict usage based on ambient values:

```
authority=[right(#authority, "/folder/file1", #read),
  right(#authority, "/folder/file2", #read), right(#authority, "/folder2/file3", #read)]
----------
caveat1 = resource(#ambient, X?), right(#authority, X?, Y?)
----------
caveat2 = time(#ambient, T?), T? < 2019-02-05T23:00:00Z // expiration date
----------
caveat3 = source_IP(#ambient, X?) | X? in ["1.2.3.4", "5.6.7.8"] // set membership
----------
```


## Semantics

A biscuit is structured as an append-only list of blocks, containing *caveats*,
and describing authorization properties.  As with Macaroons[MACAROONS],
an operation must comply with all caveats in order to be allowed by the biscuit.

Caveats are written as queries defined in a flavor of Datalog that supports
constraints on some data types[DATALOG], without support for negation. This
simplifies its implementation and makes
the caveat more precise.

### Logic language

#### Terminology

A Biscuit Datalog program contains *facts* and *rules*, which are made of *predicates*
over the following types: *symbol*, *variable*, *integer*, *string* and *date*.
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
- date in RFC 3339 format

As an example, assuming we have the following facts: `parent(#a, #b)`, `parent(#b, #c)`, `#parent(#c, #d)`.
If we apply the rule `grandparent(x?, z?) <- parent(x?, y?), parent(y? z?)`, we will
try to replace the predicates in the body by matching facts. We will get the following combinations:
- `grandparent(#a, #c) <- parent(#a, #b), parent(#b, #c)`
- `grandparent(#b, #d) <- parent(#b, #c), parent(#c, #d)`

The system will now contain the two new facts `grandparent(#a, #c)` and `grandparent(#b, #d)`.
Whenever we generate new facts, we have to reapply all of the system's rules on the facts,
because some rules might give a new result. Once rules application does not generate any new facts,
we can stop.

#### Data types

A *symbol* indicates a value that supports equality, set inclusion and set exclusion constraints.
Its internal representation has no specific meaning.

An *integer* is a signed 64 bits integer. It supports the following constraints: lower, larger,
lower or equal, larger or equal, equal, set inclusion and set exclusion.

A *string* is a suite of UTF-8 characters. It supports the following constraints: prefix, suffix,
equak, set inclusion, set exclusion.

A *date* is a 64 bit unsigned integer representing a TAI64. It supports the following constraints:
before, after.

### Authority and ambient facts

### Caveats

## Format

### Cryptographic wrapper

### Blocks

### Symbol table


## Cryptography

## References

CBOR: https://tools.ietf.org/html/rfc7049
DATALOG: "Datalog with Constraints: A Foundation for
Trust Management Languages" https://www.cs.purdue.edu/homes/ninghui/papers/cdatalog_padl03.pdf
MACAROONS: "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud" https://ai.google/research/pubs/pub41892
## Test cases

