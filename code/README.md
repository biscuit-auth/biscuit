# Experiments around signature aggregation for the biscuit token

## Requirements

We are looking for a non interactive, incrementally aggregated
signature solution for biscuit, ie a way to:
- from (message_0, privkey_0, pubkey_0), generate ([(message_0, pubkey_0)], signature0)
- from ([(message_0, pubkey_0), (message_1, pubkey_1), .. (message_n, pubkey_n)], signature_n), and (message_n+1, privkey_n+1, pubkey_n+1),
generate ([(message_0, pubkey_0), (message_1, pubkey_1), .. (message_n+1, pubkey_n+1)], signature_n+1)

It should not be possible to infer `signature_n` if we have the token at level `n+1`

## Proposals

### Pairings

The first solution that was proposed uses pairing based crypto. There are two experiments,
one with the Rust pairing crate, one with the mcl C++ library.

Performance for the Rust library is not great:

```
test bench::sign_one_block                          ... bench:   2,932,712 ns/iter (+/- 326,987)
test bench::sign_two_blocks                         ... bench:   3,234,507 ns/iter (+/- 671,200)
test bench::verify_one_block                        ... bench:  15,170,364 ns/iter (+/- 2,726,052)
test bench::verify_two_blocks                       ... bench:  22,570,853 ns/iter (+/- 2,683,514)
test bench::verify_three_blocks                     ... bench:  30,657,499 ns/iter (+/- 5,971,353)
```

But the mcl library can get at verification in 1 or 2ms.

Pairing based crypto libraries are not frequent, so it might be hard to implement in various languages

### Verifiable random functions

By reusing primitives from https://tools.ietf.org/html/draft-goldbe-vrf-01#section-5 , we can generate
aggregated non interactive proof of discrete logarithms, that match our requirements.

We have an example that uses the curve25519-dalek Rust crate, with the Ristretto group.

Here are some benchmarks for this approach:

The "first" benchmark uses the scheme described in the `DESIGN.md` document.

```
test bench::sign_first_block    ... bench:     281,512 ns/iter (+/- 51,906)
test bench::sign_second_block   ... bench:     737,981 ns/iter (+/- 190,380)
test bench::sign_third_block    ... bench:     888,010 ns/iter (+/- 129,310)
test bench::verify_one_block    ... bench:     334,755 ns/iter (+/- 25,783)
test bench::verify_three_blocks ... bench:     846,658 ns/iter (+/- 101,685)
test bench::verify_two_blocks   ... bench:     568,526 ns/iter (+/- 106,227)
```

The "second" benchmark modifies that scheme to precalculate some point additions.

```
test bench::sign_first_block    ... bench:     333,231 ns/iter (+/- 111,969)
test bench::sign_second_block   ... bench:     715,324 ns/iter (+/- 163,933)
test bench::sign_third_block    ... bench:     818,048 ns/iter (+/- 220,139)
test bench::verify_one_block    ... bench:     264,095 ns/iter (+/- 103,451)
test bench::verify_three_blocks ... bench:     434,528 ns/iter (+/- 28,993)
test bench::verify_two_blocks   ... bench:     345,233 ns/iter (+/- 22,881)
```

There's probably a lot of low hanging fruit in optimizing those, but
token attenuation and verification happening in less than 1ms makes it usable.

Since this solution uses a well known curve, there's a higher chance of getting
good quality implementations in other languages.
