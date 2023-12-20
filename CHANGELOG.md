# Changelog

## [0.5.3](https://github.com/pabrahamsson/dns-record-update/compare/v0.5.2...v0.5.3) (2023-12-20)


### Bug Fixes

* **deps:** update rust crate chrono to 0.4.31 ([f09a8a6](https://github.com/pabrahamsson/dns-record-update/commit/f09a8a6f45737674da0b8a5fec28c5863d11b12e))
* **deps:** update rust crate chrono-tz to 0.8.4 ([3ab4696](https://github.com/pabrahamsson/dns-record-update/commit/3ab4696da491cef4351e7e90704dd056ccd5115e))
* **deps:** update rust crate env_logger to 0.10.1 ([9067eab](https://github.com/pabrahamsson/dns-record-update/commit/9067eab8b261bfb723f318b30614f85a00de907e))
* **deps:** update rust crate futures-util to 0.3.29 ([6d8e411](https://github.com/pabrahamsson/dns-record-update/commit/6d8e411b70383110504c8c2a54bca90c5414139f))
* **deps:** update rust crate openssl to 0.10.61 ([136041e](https://github.com/pabrahamsson/dns-record-update/commit/136041ee83752e5b54ea60d80032fbc863297c76))
* **deps:** update rust crate serde to 1.0.193 ([4a38f3e](https://github.com/pabrahamsson/dns-record-update/commit/4a38f3ec5d5c8dd2f7247f7f6d0c5242d292dc92))
* **deps:** update rust crate serde_json to 1.0.108 ([373f220](https://github.com/pabrahamsson/dns-record-update/commit/373f220bf23dc9005fdc573ccc3c15da9b4b9982))
* **deps:** update rust crate tokio to 1.35.1 ([032b75e](https://github.com/pabrahamsson/dns-record-update/commit/032b75e612e3b766b28eead3d66a399a8b63eeb4))

## [0.5.2](https://github.com/pabrahamsson/dns-record-update/compare/v0.5.0...v0.5.2) (2023-12-20)


### Features

* Migrate back to Cloudflare ([f5a3a49](https://github.com/pabrahamsson/dns-record-update/commit/f5a3a49bad1d0dae624bbc9d4f32622e401a982e))


### Miscellaneous Chores

* release 0.5.2 ([fcf40db](https://github.com/pabrahamsson/dns-record-update/commit/fcf40db5aa1b22c8193b2933f2b789617dff2048))
* release 0.5.2 ([4705ad6](https://github.com/pabrahamsson/dns-record-update/commit/4705ad60a0c5fa953bfc578527be3acec5ec3e6c))
* release 0.5.2 ([fadfd31](https://github.com/pabrahamsson/dns-record-update/commit/fadfd3111cf3fd1c299e6eabd7a53322978df520))

## [0.4.4](https://github.com/pabrahamsson/dns-record-update/compare/v0.4.3...v0.4.4) (2023-03-18)


### Bug Fixes

* Remove chrono dependency ([eb33808](https://github.com/pabrahamsson/dns-record-update/commit/eb33808df04c55bc97f7251e90a39a9156f577bd))

## [0.4.3](https://github.com/pabrahamsson/dns-record-update/compare/v0.4.2...v0.4.3) (2023-01-14)


### Bug Fixes

* Improve error handling for dns lookups ([05402ce](https://github.com/pabrahamsson/dns-record-update/commit/05402ce87d721b0547a1694ece6fe614590b3325))
* Minor cleanup ([d6ea055](https://github.com/pabrahamsson/dns-record-update/commit/d6ea0552365f2913115f978827e9c7b2061beee9))
* **workflow:** Ajust push-to-registry inputs ([15adf9d](https://github.com/pabrahamsson/dns-record-update/commit/15adf9d2cc437f12cc93bc3078b382d713042e1f))
* **workflow:** Copy podman registry creds to Docker location ([91055be](https://github.com/pabrahamsson/dns-record-update/commit/91055be06da5f31b35bfac99a0ee80a31a0e6534))
* **workflow:** Use podman login action ([69f345e](https://github.com/pabrahamsson/dns-record-update/commit/69f345ed26312e2c6222f3fb36ff91799489196a))

## [0.4.2](https://github.com/pabrahamsson/dns-record-update/compare/v0.4.1...v0.4.2) (2023-01-13)


### Bug Fixes

* Don't fetch rrset before update + error handling ([aadc345](https://github.com/pabrahamsson/dns-record-update/commit/aadc345bcd1a20646a15887b9c6f41a37e09316d))

## [0.4.1](https://github.com/pabrahamsson/dns-record-update/compare/v0.4.0...v0.4.1) (2023-01-11)


### Bug Fixes

* Add ResourceRecordSet to Span ([9abe3c9](https://github.com/pabrahamsson/dns-record-update/commit/9abe3c95626bedbe4044bd38a38dfb7cd5729368))
