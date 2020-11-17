# Short summary of Biscuit and how it works

Biscuit is an authentication and authorization token that can be used
in software, in the same way as a session ID or JSON Web Token,
carried in a cookie or a header.

It relies on public key cryptography to verify it in any application that
knows about the public key.
If you hold a valid token, it is possible to "attenuate" it (restrict its rights)
by adding more authorization checks, while keeping a valid cryptographic
signature, without contacting the server that created the token. Each attenuation
is done by adding a new "block" of logic data and rules. It is not possible to
remove or replace a block while keeping a valid signature.

Biscuit uses a logic language called [Datalog](https://en.wikipedia.org/wiki/Datalog),
to represent its authorization rules. It can model and combine authorization policies
like role based access control or capabilities in a few lines, and even
have fine grained rules carried by the token.
As an example, you could have a file server application with a common
owner or group based access control, in which you could take your token
and derive a new one, without involving the server, that would be valid
only for reading a specific file, with an expiration date.

# Introduction to Datalog

Datalog is a declarative logic language that is a subset of Prolog.
A Datalog program contains "facts", which represent data, and
"rules", which can generate new facts from existing ones.

As an example, we could define the following facts, describing some
relationships:

```
parent("Alice", "Bob")
parent("Bob", "Charles")
parent("Charles", "Denise")
```

This could be seen as a table in a relational database:

| parent |         |         |
| ------ | -       | -       |
|        | Alice   | Bob     |
|        | Bob     | Charles |
|        | Charles | Denise  |

We can then define rules to create new facts, like this one:

```
*grandparent($0, $2) <- parent($0, $1), parent($1, $2)
```

Applying this rule will look at combinations of the `parent` facts
as defined on the right side of the arrow (the "body" of the rule),
and try to match them to the variables (`$0`, `$1`, `$2`):
- `parent("Alice", "Bob"), parent("Bob", "Charles")` matches because we can replace `$0` with `"Alice"`, `$1` with `"Bob"`, `$2` with `"Charles"`
- `parent("Alice", "Bob"), parent("Charles", "Denise")` does not match because we would get different values for the `$1` variable

For each matching combination of facts in the body, we will then
generate a fact, as defined on the left side of the arrow, the "head"
of the rule. For `parent("Alice", "Bob"), parent("Bob", "Charles")`,
we would generate `grandparent("Alice", "Charles")`. A fact can be
generated from multiple rules, but we will get only one instance of it.

Going through all the combinations, we will generate:

```
grandparent("Alice", "Charles")
grandparent("Bob", "Denise")
```

which can be seen as:

| grandparent |       |         |
| ------      | -     | -       |
|             | Alice | Charles |
|             | Bob   | Denise  |

A Fact can be created from multiple rules, and a rule can use facts
generated from previous applications. If we added the following rules:

```
*ancestor(0?, 1?) <- parent(0?, 1?)
*ancestor(0?, 2?) <- parent(0?, 1?), ancestor(1?, 2?)
```

It would generate the following facts from the first one:

```
ancestor("Alice", "Bob")
ancestor("Bob", "Charles")
ancestor("Charles", "Denise")
```

Then the second rule could apply as follows:
- `ancestor("Alice", "Charles") <- parent("Alice", "Bob"), ancestor("Bob", "Charles")`
- `ancestor("Bob", "Denise") <- parent("Bob", "Charles"), ancestor("Charles", "Denise")`

So we would have:

```
ancestor("Alice", "Bob")
ancestor("Bob", "Charles")
ancestor("Charles", "Denise")
ancestor("Alice", "Charles")
ancestor("Bob", "Denise")
```

Then we reapply the second rule:
- `ancestor("Alice", "Denise") <- parent("Alice", "Bob"), ancestor("Bob", "Denise")`

Interactions with a Datalog program are done throug queries: a query contains
a rule that we apply over the system, and it returns the generated facts.

# Datalog in Biscuit

Biscuit comes with a few specific adaptations of Datalog.

It has the following base types (for elements inside of a fact):
- integer (i64)
- string
- date (seconds from epoch, UTC)
- byte array
- symbol (interned strings that are stored in a dictionary to spare space)

Rules can have constraints on fact elements. The following rule will generate
a fact only if there's a `file` fact and its value starts with `/folder/`:
`*in_folder($0) <- file($0) @ $0 matches /folder/*`

Here are the possible constraints:
- integer: <, >, <=, >=, ==, is in set, is not in set
- string: prefix, suffix, ==, is in set, is not in set
- date: before, after
- symbol: is in set, is not in set
- byte array: ==, is in set, is not in set

Most of the authorization logic comes with "caveats": they are queries over
the Datalog facts and rules. If the query produces something, (if the underlying rule
generates one or more facts), the caveat is validated, if it does not, the
caveat fails. For a token verification to be successful, all of the caveats
must succeed.

As an example, we could have a caveat that checks the presence of a file
resource, and verifies that its filename matches a specific pattern,
using a string constraint:

```
*resource_match($0) <- resource(#ambient, $0) @ $0 matches /file[0-9]+.txt/
```

In that caveat, the resource fact must have `#ambient` as ts first element.
The `#` character indicates that it is of "symbol" type. There are two special
symbols that can appear in facts:
-`#ambient`: facts that are provided by the verifier, and that depend on the request, like which resource we want to access(file path, REST endpoint, etc), operation(read, write...), current date and time, source IP address, HTTP headers...
- `#authority`: facts defined by the token's original creator or the verifier, that indicates the basic rights of the token. Every new attenation of the token will reduce those rights by adding caveats

`#ambient` and `#authority` tokens can only be provided by the token's origin
or by the verifier, they cannot be added by attenuating the token.

# Example tokens

Let's make an example, from an S3 like application, on which we can store and
retrieve files, with users having access to "buckets" holding a list of files.

Here is a first example token, that will hold a user id. This token only
contains one block, that has been signed with the root private key. The
verifier's side knows the root public key and, upon receiving the request,
will deserialie the token and verify its signature, thus authenticating
the token.

```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "user_id"]
    authority: Block[0] {
            symbols: ["user_id"]
            context: ""
            facts: [
                user_id(#authority, "user_1234"),
            ]
            rules: []
            caveats: []
        }
    blocks: [
    ]
}
```

A block comes with new symbols it adds to the system (there's a default symbol
table that already contains values like `#authority` or `#operation`). It can
contain facts, rules and caveats.

Let's assume the user is sending this token with a `PUT /bucket_5678/folder1/hello.txt` HTTP
request. The verifier would then load the token's facts and rules, along with
facts from the request:

```
user_id(#authority, "user_1234")
operation(#ambient, #write)
resource(#ambient, "bucket_5678", "/folder1/hello.txt")
current_time(#ambient, 2020-11-17T12:00:00+00:00)
```

The verifier would also be able to load authorization data from its database,
like ownership information: `owner(#authority, "user_1234", "bucket_1234")`,
`owner(#authority, "user_1234", "bucket_5678")` `owner(#authority, "user_ABCD", "bucket_ABCD")`.
In practice,this data could be filtered by limiting it to facts related to
the current ressource, or extracting the user id from the token with a query.

The verifier can also load its own rules, like creating one specifying rights
if we own a specific folder:
```
right(#authority, $0, $1, $2) <- resource(#ambient, $0, $1), operation(#ambient, $2),
    user_id(#authority, $3), owner(#authority, $3, $0)`
```
This rule will generate a `right` fact if it finds data matching the following
variables:
- `$0`: bucket
- `$1`: file path
- `$2`: operation
- `$3`: user id

We end up with a system with the following facts:

```
user_id(#authority, "user_1234")
operation(#ambient, #write)
resource(#ambient, "bucket_5678", "/folder1/hello.txt")
current_time(#ambient, 2020-11-17T12:00:00+00:00)
owner(#authority, "user_1234", "bucket_1234")
owner(#authority, "user_1234", "bucket_5678")
owner(#authority, "user_ABCD", "bucket_ABCD")
right(#authority, "bucket_5678", "/folder1/hello.txt", #write)
```

At last, the verifier provides a caveat to check that we have the rights for this
operation:

```
caveat1() <- right(#authority, $0, $1, $2), resource(#ambient, $0, $1), operation(#ambient, $2)
```

Here we can find matching facts, so the request succeeds. If the request was
done on `bucket_ABCD`, we would not be able to generate the `right` fact for
it and the request would fail.

Now, what if we wanted to limit access to reading `/folder1/hello.txt` in
`bucket_5678`?

We could ask the authorization server to generate a token with only that specific
access:

```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id"]
    authority: Block[0] {
            symbols: []
            context: ""
            facts: [
                right(#authority, "bucket_5678", "/folder1/hello.txt", #read)
            ]
            rules: []
            caveats: []
        }
    blocks: [
    ]
}
```

Without a `user_id`, the verifier would be unable to generate more `right` facts
and would only have the one provided by the token.

But we could also take the first token, and restrict it by adding a block containing
a new caveat:

```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "user_id"]
    authority: Block[0] {
            symbols: ["user_id"]
            context: ""
            facts: [
                user_id(#authority, "user_1234"),
            ]
            rules: []
            caveats: []
        }
    blocks: [
        Block[1] {
            symbols: ["caveat1", "read"]
            context: ""
            facts: []
            rules: []
            caveats: [
                *caveat1() <- resource(#ambient, "bucket_5678", "/folder1/hello.txt"), operation(#ambient, #read)
            ]
        }

    ]
}
```

With that token, if the holder tried to do a `PUT /bucket_5678/folder1/hello.txt`
request, we ould end up with the following facts:

```
user_id(#authority, "user_1234")
operation(#ambient, #write)
resource(#ambient, "bucket_5678", "/folder1/hello.txt")
current_time(#ambient, 2020-11-17T12:00:00+00:00)
owner(#authority, "user_1234", "bucket_1234")
owner(#authority, "user_1234", "bucket_5678")
owner(#authority, "user_ABCD", "bucket_ABCD")
right(#authority, "bucket_5678", "/folder1/hello.txt", #write)
```

The verifier's caveat would still succeed, but the caveat from block 1 would
fail because it cannot find `operation(#ambient, #read)`.

By playing with the facts provided on the token and verifier sides, generating
data through rules, and restricting access with a serie of caveats, it is
possible to build powerful rights management systems, with fine grained controls,
in a mall, cryptographically secured token.
