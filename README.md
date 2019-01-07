# Biscuit authentication token

<img src="https://raw.githubusercontent.com/CleverCloud/biscuit/master/assets/brown.png" width="300">

*logo by [Mathias Adam](http://www.madgraphism.com/)*

Biscuit is a (in development) authentication token for microservices
architectures with the following properties:

- distributed authorization: any node could validate the token only with public information
- offline delegation: a new, valid token can be created from another one by attenuating its rights,
by its holder, without communicating with the issuer or the verifier
- capabilities based: authorization in microservices should be tied to rights related to the request,
instead of relying to an identity that might not make sense to the verifier
- flexible rights managements: the token specifies a pattern based right specification
and attenuation syntax taht can map to other rights management systems
- small enough to fit anywhere (cookies, etc)

Non goals:
- this is not a new authentication protocol. Biscuit tokens can be used as opaque tokens delivered by other systems such as OAuth
- revocation: while tokens come with expiration dates, revocation requires external state management
