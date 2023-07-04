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

Biscuit uses a logic language based on [Datalog](https://en.wikipedia.org/wiki/Datalog),
to represent its authorization rules. It can model and combine authorization policies
like role-based access control or capabilities in a few lines, and even
have fine grained rules carried by the token.
As an example, you could have a file server application with a common
owner or group-based access control, in which you could take your token
and derive a new one, without involving the server, that would be valid
only for reading a specific file, with an expiration date.

# Introduction to Datalog

Datalog is a declarative logic language that is a subset of Prolog.
A Datalog program contains "facts", which represent data, and
"rules", which can generate new facts from existing ones.

As an example, we could define the following facts, describing some
relationships:

```
parent("Alice", "Bob");
parent("Bob", "Charles");
parent("Charles", "Denise");
```

This means that Alice is Bob's parent, and so on.

This could be seen as a table in a relational database:

| parent |         |         |
| ------ | -       | -       |
|        | Alice   | Bob     |
|        | Bob     | Charles |
|        | Charles | Denise  |

We can then define rules to create new facts, like this one: (a rule is made of a "head" on the left of `<-` indicating the data that is generated, variables are introduced with the `$` sign)

```
grandparent($grandparent, $child) <- parent($grandparent, $parent), parent($parent, $child)
```

Applying this rule will look at combinations of the `parent` facts
as defined on the right side of the arrow (the "body" of the rule),
and try to match them to the variables (`$grandparent`, `$parent`, `$child`):
- `parent("Alice", "Bob"), parent("Bob", "Charles")` matches because we can replace `$grandparent` with `"Alice"`, `$parent` with `"Bob"`, `$child` with `"Charles"`
- `parent("Alice", "Bob"), parent("Charles", "Denise")` does not match because we would get different values for the `$parent` variable

For each matching combination of facts in the body, we will then
generate a fact, as defined on the left side of the arrow, the "head"
of the rule. For `parent("Alice", "Bob"), parent("Bob", "Charles")`,
we would generate `grandparent("Alice", "Charles")`. A fact can be
generated from multiple rules, but we will get only one instance of it.

Going through all the combinations, we will generate:

```
grandparent("Alice", "Charles");
grandparent("Bob", "Denise");
```

which can be seen as:

| grandparent |       |         |
| ------      | -     | -       |
|             | Alice | Charles |
|             | Bob   | Denise  |

A Fact can be created from multiple rules, and a rule can use facts
generated from previous applications. If we added the following rules:

```
ancestor($parent, $child) <- parent($parent, $child);
ancestor($parent, $descendant) <- parent($parent, $child), ancestor($child, $descendant);
```

It would generate the following facts from the first one:

```
ancestor("Alice", "Bob");
ancestor("Bob", "Charles");
ancestor("Charles", "Denise");
```

Then the second rule could apply as follows:

- `ancestor("Alice", "Charles") <- parent("Alice", "Bob"), ancestor("Bob", "Charles")`
- `ancestor("Bob", "Denise") <- parent("Bob", "Charles"), ancestor("Charles", "Denise")`

So we would have:

```
ancestor("Alice", "Bob");
ancestor("Bob", "Charles");
ancestor("Charles", "Denise");
ancestor("Alice", "Charles");
ancestor("Bob", "Denise");
```

Then we reapply the second rule:

- `ancestor("Alice", "Denise") <- parent("Alice", "Bob"), ancestor("Bob", "Denise")`

So in the end we would have:

```
ancestor("Alice", "Bob");
ancestor("Bob", "Charles");
ancestor("Charles", "Denise");
ancestor("Alice", "Charles");
ancestor("Bob", "Denise");
ancestor("Alice", "Denise");
```

Interactions with a Datalog program are done through queries: **a query contains
a rule** that we apply over the system, and **it returns the generated facts**.

# Datalog in Biscuit

Biscuit comes with a few specific adaptations of Datalog.

It has the following base types (for elements inside of a fact):

- integer (i64)
- string
- date (seconds from epoch, UTC)
- byte array
- boolean (true or false)
- set: a deduplicated list of values, that can be of any type except variables or sets

Rules can contain expressions that evaluate variables defined in the other
predicates. An expression must always evaluate to a boolean. If it returns
false, the rule evaluation fails. The following rule will generate a fact only
if there's a `file` fact and its value starts with `/folder/`:

`in_folder($path) <- file($path), $path.starts_with(/folder/*)`

Here are the possible operations:

- integer: <, >, <=, >=, ==, +, -, *, /
- string: .starts_with(string), .ends_with(string), .matches(regex string), ==
- date: <=, >=
- byte array: ==, is in set, is not in set
- boolean: &&,  ||, !
- set: .contains(value)

## Checks

The first part of the authorization logic comes with _checks_: they are queries over
the Datalog facts. If the query produces something, (if the underlying rule
generates one or more facts), the check is validated, if it does not, the
check fails. For a token verification to be successful, all of the checks
must succeed.

As an example, we could have a check that tests the presence of a file
resource, and verifies that its filename matches a specific pattern,
using a string expression:

```
check if
  resource($path),
  $path.matches("file[0-9]+.txt")
```

This check matches only if there exists a `resource($path)` fact for
which `$path` matches a pattern.

## Allow and deny policies

The validation in Biscuit relies on a list of allow or deny policies, that are
evaluated after all of the checks have succeeded. Like checks; they are queries
that must find a matching set of facts to succeed. If they do not match, we try
the next one. If they succeed, an allow policy will make the request validation
succeed, while a deny policy will make it fail. If no policy matched, the
validation will fail.

Example policies:

```
// verifies that we have rights for this request
allow if
  resource($res),
  operation($op),
  right($res, $op)

// otherwise, allow if we're admin
allow if is_admin()

// catch all if non of the policies matched
deny if true
```

##### Revocation identifiers

The verifier will generate a list of facts indicating revocation identifiers for
the token. They uniquely identify the token and each of its parent tokens through
a series of SHA256 hashes. That way, if a token is revoked, we will be able to
refuse all the tokens derived from it.

To check revocation status, we can either:
- query the list of revocation tokens: `revocation($index, $id) <- revocation_id($index, $id)` then verify their presence in a revocation list
- load a policy with the list of revoked tokens: `deny if revocation_id($index, $id), [ hex:1234..., hex:4567...].contains($id)`

The hashes are generated from the serialized blocks and the corresponding keys,
so if you generate multiple tokens with the same root key and same authority
block, they will have the same revocation identifier. To avoid that, you can
add unique data to the block, like a random value, a UUID identifying that
token chain, a date, etc.

# Example tokens

Let's make an example, from an S3-like application, on which we can store and
retrieve files, with users having access to "buckets" holding a list of files.

Here is a first example token, that will hold a user id. This token only
contains one block, that has been signed with the root private key. The
verifier's side knows the root public key and, upon receiving the request,
will deserialize the token and verify its signature, thus authenticating
the token.

```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "user_id"]
    authority: Block[0] {
            symbols: ["user_id"]
            context: ""
            version: 1
            facts: [
                user_id("user_1234"),
            ]
            rules: []
            checks: []
        }
    blocks: [
    ]
}
```

Let's unpack what's displayed here:

 - `symbols` carries a list of symbols used in the biscuit.
 - `authority` this block carries information provided by the token creator. It gives the initial scope of the biscuit.
 - `blocks` carries a list of blocks, which can refine the scope of the biscuit

Here, `authority` provides the initial block, which can be refined in subsequent blocks.

A block comes with new symbols it adds to the system. It can
contain facts, rules and checks. A block contains:

 - `symbols`:  a block can introduce new symbols: these symbols are available in the current block, _and the following blocks_. **It is not possible to re-declare an existing symbol**.
 - `context`: free form text used either for documentation purpose, or to give a hint about which facts should be retrieved from DB
 - `facts`: each block can define new facts
 - `rules` each block can define new rules but they only have access to facts from the current and previous blocks
 - `checks` each block can define new checks (queries that need to match in order to make the biscuit valid) but they only have access to facts from the current and previous blocks

Let's assume the user is sending this token with a `PUT /bucket_5678/folder1/hello.txt` HTTP
request. The verifier would then load the token's facts and rules, along with
facts from the request:

```
user_id("user_1234");
operation("write");
resource("bucket_5678", "/folder1/hello.txt");
current_time(2020-11-17T12:00:00+00:00);
```

The verifier would also be able to load authorization data from its database,
like ownership information: `owner("user_1234", "bucket_1234")`,
`owner("user_1234", "bucket_5678")` `owner("user_ABCD", "bucket_ABCD")`.
In practice, this data could be filtered by limiting it to facts related to
the current resource, or extracting the user id from the token with a query.

The verifier can also load its own rules, like creating one specifying rights
if we own a specific folder:

```
// the resource owner has all rights on the resource
right($bucket, $path, $operation) <-
  resource($bucket, $path),
  operation($operation),
  user_id($id),
  owner($id, $bucket)
```

This rule will generate a `right` fact if it finds data matching the variables.

We end up with a system with the following facts:

```
user_id("user_1234");
operation("write");
resource("bucket_5678", "/folder1/hello.txt");
current_time(2020-11-17T12:00:00+00:00);
owner("user_1234", "bucket_1234");
owner("user_1234", "bucket_5678");
owner("user_ABCD", "bucket_ABCD");
right("bucket_5678", "/folder1/hello.txt", "write");
```

At last, the verifier provides a policy to test that we have the rights for this
operation:

```
allow if
  right($bucket, $path, $operation),
  resource($bucket, $path),
  operation($operation)
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
            version: 1
            facts: [
                right("bucket_5678", "/folder1/hello.txt", "read")
            ]
            rules: []
            checks: []
        }
    blocks: [
    ]
}
```

Without a `user_id`, the verifier would be unable to generate more `right` facts
and would only have the one provided by the token.

But we could also take the first token, and restrict it by adding a block containing
a new check:

```
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "user_id"]
    authority: Block[0] {
            symbols: ["user_id"]
            context: ""
            version: 1
            facts: [
                user_id("user_1234"),
            ]
            rules: []
            checks: []
        }
    blocks: [
        Block[1] {
            symbols: ["caveat1", "read"]
            context: ""
            version: 1
            facts: []
            rules: []
            checks: [
                check if resource("bucket_5678", "/folder1/hello.txt"), operation("read")
            ]
        }

    ]
}
```

With that token, if the holder tried to do a `PUT /bucket_5678/folder1/hello.txt`
request, we would end up with the following facts:

```
user_id("user_1234");
operation("write");
resource("bucket_5678", "/folder1/hello.txt");
current_time(2020-11-17T12:00:00+00:00);
owner("user_1234", "bucket_1234");
owner("user_1234", "bucket_5678");
owner("user_ABCD", "bucket_ABCD");
right("bucket_5678", "/folder1/hello.txt", "write");
```

The verifier's policy would still succeed, but the check from block 1 would
fail because it cannot find `operation("read")`.

By playing with the facts provided on the token and verifier sides, generating
data through rules, and restricting access with a series of checks, it is
possible to build powerful rights management systems, with fine grained controls,
in a small, cryptographically secured token.
