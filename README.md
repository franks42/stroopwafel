# stroopwafel

Capability-based authorization tokens for Clojure.

## Acknowledgments

Stroopwafel builds on the vision of [Biscuit](https://github.com/eclipse-biscuit/biscuit) — cryptographically signed, append-only authorization tokens with Datalog-based policy evaluation — and is derived from [KEX](https://github.com/serefayar/kex), Seref Ayar's elegant proof-of-concept that demonstrated these ideas can be expressed naturally in Clojure. Stroopwafel aims to bring KEX to production quality with full Biscuit feature parity, using [CEDN](https://github.com/franks42/canonical-edn) for deterministic serialization.

## License

Copyright (c) Frank Siebenlist. Distributed under the [Eclipse Public License v2.0](LICENSE).
KEX attribution preserved per EPL-1.0.
