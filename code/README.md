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

#### Performance

Performance for the Rust library is not great:

```
test bench::sign_one_block                          ... bench:   2,932,712 ns/iter (+/- 326,987)
test bench::sign_two_blocks                         ... bench:   3,234,507 ns/iter (+/- 671,200)
test bench::verify_one_block                        ... bench:  15,170,364 ns/iter (+/- 2,726,052)
test bench::verify_two_blocks                       ... bench:  22,570,853 ns/iter (+/- 2,683,514)
test bench::verify_three_blocks                     ... bench:  30,657,499 ns/iter (+/- 5,971,353)
```

But the mcl library can get at verification in 1 or 2ms.

#### Signature overhead

The first group's points can be stored in 48 bytes, the second group's in 96 bytes.
Assuming we use the first group to get smaller points (probably at the price of a reduced security bound),
We would need to store one G1 point per block, and one G2 point.

So, for:
- 1 block: 1 * 48 + 96 = 144 bytes
- 2 blocks: 2 * 48 + 96 = 192 bytes
- 5 blocks: 5 * 48 + 96 = 336 bytes
- 10 blocks: 10 * 48 + 96 = 576 bytes
- 20 blocks: 20 * 48 + 96 = 1056 bytes

Pairing based crypto libraries are not frequent, so it might be hard to implement in various languages

### Verifiable random functions

By reusing primitives from https://tools.ietf.org/html/draft-goldbe-vrf-01#section-5 , we can generate
aggregated non interactive proof of discrete logarithms, that match our requirements.

We have an example that uses the curve25519-dalek Rust crate, with the Ristretto group.

#### Performance

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

#### Signature overhead

a Ristretto point can be stored in 32 bytes, a Scalar can be stored in 32 bytes

With the first method, we will store 2 points (pubkey and gamma) and 1 scalar
per block, and 1 point and 1 scalar in the signature.
With the second method, we will store 1 point (pubkey) and 1 scalar per block,
and 2 points and 1 scalar in the signature.

So, for the first method:
- 1 block: 1 * 96 + 64 = 160 bytes
- 2 blocks: 2 * 96 + 64 = 256 bytes
- 5 blocks: 5 * 96 + 64 = 544 bytes
- 10 blocks: 10 * 96 + 64 = 1024 bytes
- 20 blocks: 20 * 96 + 64 = 1984 bytes

For the second method:
- 1 block: 1 * 64 + 96 = 160 bytes
- 2 blocks: 2 * 64 + 96 = 224 bytes
- 5 blocks: 5 * 64 + 96 = 416 bytes
- 10 blocks: 10 * 64 + 96 = 736 bytes
- 20 blocks: 10 * 64 + 96 = 1376 bytes

Since this solution uses a well known curve, there's a higher chance of getting
good quality implementations in other languages.

### Challenge tokens

Another method based on a more classical PKI, with a last challenge to prove
that we own the last key.

Here's a description of the scheme:

```
(pk1, sk1) = keygen()
(pk2, sk2) = keygen()
s1 = sign(sk1, caveat1+pk2)
token1=caveat1+pk2+s1+sk2

Minting a new token:
(pk3, sk3) = keygen()
s2 = sign(sk2, caveat2+pk3)
token2=caveat1+pk2+s1+caveat2+pk3+s2+sk3

Sending token2 for verification:
verif_token2=caveat1+pk2+s1+caveat2+pk3+s2
h = sign(sk3, nonce+time+verif_token2)
sending verif_token2+h

The verifier knows pk1 and can check the chain, and h allows checking that we hold sk3
```

#### Performance

Here are some benchmarks for this approach:

test bench::sign_first_block    ... bench:     325,113 ns/iter (+/- 22,812)
test bench::sign_second_block   ... bench:     402,085 ns/iter (+/- 36,133)
test bench::sign_third_block    ... bench:     405,621 ns/iter (+/- 28,162)
test bench::verify_one_block    ... bench:     308,992 ns/iter (+/- 32,920)
test bench::verify_two_blocks   ... bench:     472,676 ns/iter (+/- 97,749)
test bench::verify_three_blocks ... bench:     624,811 ns/iter (+/- 63,081)

#### Signature overhead

a Ristretto point can be stored in 32 bytes, a Scalar can be stored in 32 bytes

For each block, we will store 1 point (public key) and 2 scalars (signature).
There's an additional scalar to store the next private key.
The challenge token has 1 point (public key) and 2 scalars (signature) per block,
and there's 1 more point, and 2 scalars (signature), along with the challenge

This gives the following:
- 1 block: 1 * 96 + 32 = 128 bytes
- 2 blocks: 2 * 96 + 32 = 224 bytes
- 5 blocks: 5 * 96 + 32 = 512 bytes
- 10 blocks: 10 * 96 + 32 = 992 bytes
- 20 blocks: 20 * 96 + 32 = 1952 bytes

And for the challenge token:
- 1 block: 1 * 96 + 96 = 192 bytes
- 2 blocks: 2 * 96 + 96 = 288 bytes
- 5 blocks: 5 * 96 + 96 = 576 bytes
- 10 blocks: 10 * 96 + 96 = 1056 bytes
- 20 blocks: 20 * 96 + 96 = 2016 bytes

About the same size as the first VRF solution, but the challenge token makes it bigger

It can use well known curves and signature algorithms (the example code uses Schnorr signatures).
It has som slight differences in behaviour with the other methods, though:
- generating a verif token requires access to the token (ie no HttpOnly cookies)
- once a challenge token is generated, it cannot be attenuated again (might be a good thing or bad thing depending on the context)

## Benchmarks summary

### Signing

|           | 1 block | 2 blocks | 3 blocks |
| --------- | ------- | -------- | -------- |
| pairing   | 2932 μs | 3234 μs  |          |
| VRF 1     |  281 μs |  737 μs  | 888 μs   |
| VRF 2     |  333 μs |  715 μs  | 818 μs   |
| challenge |  325 μs |  402 μs  | 405 μs   |

### Verifying

|           | 1 block  | 2 blocks | 3 blocks |
| --------- | -------- | -------- | -------- |
| pairing   | 15170 μs | 22570 μs | 30657 μs |
| VRF 1     |   334 μs |   846 μs |   568 μs |
| VRF 2     |   264 μs |   434 μs |   345 μs |
| challenge |   308 μs |   472 μs |   624 μs |

### Size overhead

(in bytes)

|                             | 1 block | 2 blocks | 5 blocks | 10 blocks | 20 blocks |
| --------------------------- | ------- | -------- | -------- | --------- | --------- |
| pairing                     | 144     | 192      | 336      | 576       | 1056      |
| VRF 1                       | 160     | 256      | 544      | 1024      | 1984      |
| VRF 2                       | 160     | 224      | 416      | 736       | 1376      |
| challenge (base token)      | 128     | 224      | 512      | 992       | 1952      |
| challenge (challenge token) | 192     |  288     | 576      | 1056      | 2016      |
