# Biscuit authentication/authorization token

[![Join the chat at https://gitter.im/CleverCloud/biscuit](https://badges.gitter.im/CleverCloud/biscuit.svg)](https://gitter.im/CleverCloud/biscuit?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

<img src="https://raw.githubusercontent.com/biscuit-auth/biscuit/master/assets/brown.png" width="200">

<https://biscuitsec.org>

## Goals

Biscuit is an authentication and authorization token for microservices
architectures with the following properties:

- **distributed authentication**: any node could validate the token only with public
  information;
- **offline delegation**: a new, valid token can be created from another one by
  attenuating its rights, by its holder, without communicating with anyone;
- **capabilities based**: authorization in microservices should be tied to rights
  related to the request, instead of relying to an identity that might not make
  sense to the verifier;
- **flexible rights managements**: the token uses a logic language to specify attenuation
  and add bounds on ambient data, it can model from small rules like expiration dates,
  to more flexible architectures like hierarchical roles and user delegation;
- **small** enough to fit anywhere (cookies, etc).

## Non goals
- This is not a new authentication protocol. Biscuit tokens can be used as
  opaque tokens delivered by other systems such as OAuth.
- Revocation: Biscuit generates unique revocation identifiers for each token,
and can provide expiration dates as well, but revocation requires external
state management (revocation lists, databases, etc) that is outside of this
specification.

## Roadmap

You can follow the next steps on the [roadmap](https://github.com/biscuit-auth/biscuit/issues/12).

Current status:
- the credentials language, cryptographic primitives and serialization format are done
- we have implementations for biscuits v2 in
  - [Rust](https://github.com/biscuit-auth/biscuit-rust)
  - [Web Assembly](https://github.com/biscuit-auth/biscuit-wasm) (based on the Rust version)
  - [Haskell](https://github.com/divarvel/biscuit-haskell)
- we have implementations for biscuits v1 in
  - [Java](https://github.com/clevercloud/biscuit-java) (migration to v2 is in progress)
  - [Go](https://github.com/flynn/biscuit-go)
- a website with documentation and an interactive playground is live at <https://biscuitsec.org>
- Currently deploying to real world use cases such as [Apache Pulsar](https://github.com/clevercloud/biscuit-pulsar) at [Clever Cloud](https://www.clever-cloud.com/)
- looking for an audit of the token's design, cryptographic primitives and implementations

## How to help us?

- provide use cases that we can test the token on (some specific kind of caveats, auth delegation, etc)
- cryptographic design audit: we need reviews of algorithms, their usage and implementation in various languages
- add support for biscuit v2 to java and go implementations

## Project organisation

- `SUMMARY.md`: introduction to Biscuit from a user's perspective
- `SPECIFICATIONS.md` is the description of Biscuit, its format and behaviour
- `DESIGN.md` holds the initial ideas about what Biscuit should be
- `experimentations/` holds initial code examples for the crypographic schemes and caveat language. `code/biscuit-poc/` contains an experimental version of Biscuit, built to explore API issues

## License

Licensed under Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

logo by [Mathias Adam](http://www.madgraphism.com/)

originally created at [Clever Cloud](https://www.clever-cloud.com/)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be licensed as above, without any additional terms or
conditions.
