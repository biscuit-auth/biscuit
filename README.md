# Biscuit authentication/authorization token

[![Join the chat at https://gitter.im/CleverCloud/biscuit](https://badges.gitter.im/CleverCloud/biscuit.svg)](https://gitter.im/CleverCloud/biscuit?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

<img src="https://raw.githubusercontent.com/CleverCloud/biscuit/master/assets/brown.png" width="200">

## Goals

Biscuit is an authentication and authorization token for microservices
architectures with the following properties:

- distributed authentication: any node could validate the token only with public
  information;
- offline delegation: a new, valid token can be created from another one by
  attenuating its rights, by its holder, without communicating with anyone;
- capabilities based: authorization in microservices should be tied to rights
  related to the request, instead of relying to an identity that might not make
  sense to the verifier;
- flexible rights managements: the token uses a logic language to specify attenuation
  and add bounds on ambient data;
- small enough to fit anywhere (cookies, etc).

## Non goals
- This is not a new authentication protocol. Biscuit tokens can be used as
  opaque tokens delivered by other systems such as OAuth.
- Revocation: while tokens come with expiration dates and revocation ids,
  revocation still requires external state management that we will not specify.

## Roadmap

You can follow the next steps on the [roadmap](https://github.com/CleverCloud/biscuit/issues/12).

Current status:
- the credential language, cryptographic primitives and serialization format are done
- we have implementations in [Rust](https://github.com/clevercloud/biscuit-rust), [Java](https://github.com/clevercloud/biscuit-java) and [Web Assembly](https://github.com/clevercloud/biscuit-wasm) (based on the Rust version)
- Currently deploying to real world use cases such as [Apache Pulsar](https://github.com/clevercloud/biscuit-pulsar)
- looking for an audit of the token's design, cryptographic primitives and implementations

## How to help us?

- provide use cases that we can test the token on (some specific kind of caveats, auth delegation, etc)
- cryptographic design audit: we need to decide on a cryptographic scheme that will be strong enough

## Project organisation

- `DESIGN.md` holds the current ideas about what Biscuit should be
- `SPECIFICATIONS.md` is the in progress description of Biscuit, its format and behaviour
- `experimentations/` holds code examples for the crypographic schemes and caveat language. `code/biscuit-poc/` contains an experimental version of Biscuit, built to explore API issues

## License

Licensed under Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

logo by [Mathias Adam](http://www.madgraphism.com/)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be licensed as above, without any additional terms or
conditions.
