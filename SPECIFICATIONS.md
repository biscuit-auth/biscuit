# Biscuit, a bearer token with offline attenuation and decentralized verification

placeholder: please see [PR 20](https://github.com/CleverCloud/biscuit/pull/20)
for the current version of the specifications with comments.

## Introduction

Biscuit is a bearer token that supports offline attenuation, can be verified
by any system that would hold some public information, and provides a flexible
caveat language based on logic programming. It is serialized as
[Concise Binary Object Representation](https://tools.ietf.org/html/rfc7049),
and designed to be small enough for storage HTTP cookies.

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

### Logic language

### Authority and ambient facts

### Caveats

## Format

### Cryptographic wrapper

### Blocks

### Symbol table


## Cryptography


## Test cases
