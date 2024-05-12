# Biscuit authentication/authorization token

[Join the Matrix chat](https://matrix.to/#/#biscuit-auth:matrix.org)

<img src="https://raw.githubusercontent.com/biscuit-auth/biscuit/master/assets/brown.png" width="200">

<https://www.biscuitsec.org>

## Version

The stable version of the specification is at [SPECIFICATIONS.md](https://github.com/biscuit-auth/biscuit/blob/main/SPECIFICATIONS.md). The currently in development version is on the [dev branch](https://github.com/biscuit-auth/biscuit/blob/dev/SPECIFICATIONS.md).

## Motivation, goals, non-goals

See <https://www.biscuitsec.org/docs/why-biscuit/>. 

## Try it out

Biscuit tokens can be created, attenuated, inspected and authorized from your browser: <https://www.biscuitsec.org/docs/tooling/>

## Roadmap

You can follow the next steps on the [roadmap](https://github.com/biscuit-auth/biscuit/issues/12).

Current status:

- the credentials language, cryptographic primitives and serialization format are done
- we have implementations for biscuits v2 in
  - [Rust](https://github.com/biscuit-auth/biscuit-rust)
  - [Web Assembly](https://github.com/biscuit-auth/biscuit-wasm) (based on the Rust version)
  - [Python](https://github.com/biscuit-auth/biscuit-python) (based on the Rust version)
  - [Haskell](https://github.com/biscuit-auth/biscuit-haskell)
- we have implementations for biscuits v1 in
  - [Java](https://github.com/clevercloud/biscuit-java) (migration to v2 is in progress)
  - [Go](https://github.com/biscuit-auth/biscuit-go)
- a website with documentation and an interactive playground is live at <https://biscuitsec.org>
- Currently deploying to real world use cases such as [Apache Pulsar](https://github.com/clevercloud/biscuit-pulsar) at [Clever Cloud](https://www.clever-cloud.com/)
- looking for an audit of the token's design, cryptographic primitives and implementations

## Feature support

The different implementations are following the specification closely, but parts of it may take some time to be fully implemented, so here is the current list of supported features per version:

* ✅ full support
* 🚧 partial support
* ❌ not supported yet

|                    | Rust | Haskell | Java | Go | Python | C# | Zig |
|--------------------|------|---------|------|----|--------|----|-----|
|**v2**              |  ✅  |    ✅   |  ✅  | ✅ |   ✅   |  ? |   ? |
|--------------------|------|---------|------|----|--------|----|-----|
|**v3**              | ✅   | ✅      |  🚧  | ❌ |   ❌   | ?  | ?   |
| scopes             | ✅   | ✅      |  ✅  |    |        |    |     |
| check all          | ✅   | ✅      |  ✅  |    |        |    |     |
| bitwise operations | ✅   | ✅      |  ✅  |    |        |    |     |
| third party blocks | ✅   | ✅      |  🚧  |    |        |    |     |


## How to help us?

- provide use cases that we can test the token on (some specific kind of checks, auth delegation, etc)
- cryptographic design audit: we need reviews of algorithms, their usage and implementation in various languages
- add support for biscuit v2 to java and go implementations

## Project organisation

- `SPECIFICATIONS.md` is the description of Biscuit, its format and behaviour
- `biscuit-web-key/` is a specification for publishing biscuit public keys
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
