# Changelog

## [1.4.1](https://github.com/postalsys/certs/compare/v1.4.0...v1.4.1) (2026-09-10)


### Bug Fixes

* key a domain under the name it canonicalizes to, however it was spelled ([ea57976](https://github.com/postalsys/certs/commit/ea579767da711a6c7657a2f59a31632ec3da7ba8))

## [1.4.0](https://github.com/postalsys/certs/compare/v1.3.0...v1.4.0) (2026-09-09)


### Features

* say whether this call failed to renew, not only what the record last recorded ([37b1344](https://github.com/postalsys/certs/commit/37b13446891cb5c8dd93b5f050e39b6e3e20b76c))

## [1.3.0](https://github.com/postalsys/certs/compare/v1.2.1...v1.3.0) (2026-09-08)


### Features

* refuse a constructor option the library would not read ([fffab8e](https://github.com/postalsys/certs/commit/fffab8eccc62f1c54481827af043da6685e63baf))

## [1.2.1](https://github.com/postalsys/certs/compare/v1.2.0...v1.2.1) (2026-09-08)


### Bug Fixes

* act on the security and correctness review of the in-house ACME client ([e6f1371](https://github.com/postalsys/certs/commit/e6f1371c34e0b71989284d7c2f0f9784fdc33ddd))

## [1.2.0](https://github.com/postalsys/certs/compare/v1.1.1...v1.2.0) (2026-09-08)


### Features

* replace @root/acme with an in-house RFC 8555 client ([8f2d344](https://github.com/postalsys/certs/commit/8f2d34464cf0c55fb20522d1c06253f0ca0e2d06))

## [1.1.1](https://github.com/postalsys/certs/compare/v1.1.0...v1.1.1) (2026-09-07)


### Bug Fixes

* declare the Node 20 floor this package already has ([1f0a7d4](https://github.com/postalsys/certs/commit/1f0a7d4db4d27cbfc435d7a6ef7f0f39b1a94e47))
* **deps:** update joi to 18.2.8 and undici to 7.29.1 ([2464c07](https://github.com/postalsys/certs/commit/2464c0733919325369e92d65854535796b83f00d))

## [1.1.0](https://github.com/postalsys/certs/compare/v1.0.19...v1.1.0) (2026-09-05)


### Features

* send ACME requests through a caller-supplied undici dispatcher ([11bee5f](https://github.com/postalsys/certs/commit/11bee5f77cdbfabb65722ae96bf1f99a6c017704))

## [1.0.19](https://github.com/postalsys/certs/compare/v1.0.18...v1.0.19) (2026-08-31)


### Bug Fixes

* renew certificates proportionally to their lifetime ([363d3c6](https://github.com/postalsys/certs/commit/363d3c68de452ebe3406858c9006d571ff314565))

## [1.0.18](https://github.com/postalsys/certs/compare/v1.0.17...v1.0.18) (2026-08-24)


### Bug Fixes

* **deps:** update ioredfour to 1.4.3, joi to 18.2.5 and drop the ioredis cap ([43a032d](https://github.com/postalsys/certs/commit/43a032d0bd725bdee937b8fb06aca9546578ab57))

## [1.0.17](https://github.com/postalsys/certs/compare/v1.0.16...v1.0.17) (2026-08-12)


### Bug Fixes

* **deps:** move to joi 18 and replace deprecated msgpack5 ([145d9a5](https://github.com/postalsys/certs/commit/145d9a579a616a2c22a60d981893109f5818e2b8))

## [1.0.16](https://github.com/postalsys/certs/compare/v1.0.15...v1.0.16) (2026-07-20)


### Bug Fixes

* **deps:** update ioredfour to 1.4.2 ([11a565e](https://github.com/postalsys/certs/commit/11a565e5ea7e8ca859dc6719bd5ff3223d2c996c))

## [1.0.15](https://github.com/postalsys/certs/compare/v1.0.14...v1.0.15) (2026-06-13)


### Bug Fixes

* bumped deps ([90788b8](https://github.com/postalsys/certs/commit/90788b881a1d47ecaed2083af3f07436a44cbe09))
* Bumped deps ([471f304](https://github.com/postalsys/certs/commit/471f304bc25327c2738a87b6a85a43b3c24433a5))

## [1.0.14](https://github.com/postalsys/certs/compare/v1.0.13...v1.0.14) (2026-03-23)


### Bug Fixes

* add test suite and CI workflow ([1c5569c](https://github.com/postalsys/certs/commit/1c5569c02386e8ed167672a78980e6f621a8db4a))
* bumped deps ([2673ff0](https://github.com/postalsys/certs/commit/2673ff0db815f0b33b060afba3f9cdfe035cbd44))
* update test matrix to Node 20, 22, 24 ([c20356b](https://github.com/postalsys/certs/commit/c20356b27e8c5e648657c404c57f22375ded0d42))

## [1.0.13](https://github.com/postalsys/certs/compare/v1.0.12...v1.0.13) (2026-03-23)


### Bug Fixes

* bumped deos ([3d8cc4c](https://github.com/postalsys/certs/commit/3d8cc4ce6f5a58c25f9780076dc8adc99f26d279))
* update release workflow to Node 24 and use trusted publishers ([2392f54](https://github.com/postalsys/certs/commit/2392f547f421bbf83f32ffe4e06cbbf3f4cfc80c))

## [1.0.12](https://github.com/postalsys/certs/compare/v1.0.11...v1.0.12) (2025-09-29)


### Bug Fixes

* Bumped deps ([762fc6e](https://github.com/postalsys/certs/commit/762fc6e0c82c63427a46fe99b23db72b8f2c7333))
* do not use uuid library ([5d6716f](https://github.com/postalsys/certs/commit/5d6716f1c856aa9deadd596ac0b85d6433b3fec0))

## [1.0.11](https://github.com/postalsys/certs/compare/v1.0.10...v1.0.11) (2024-09-08)


### Bug Fixes

* **punycode:** Replaced punycode module with punycode.js ([c474acb](https://github.com/postalsys/certs/commit/c474acb46f90885f722a3bbd74ba824bf2a4cdae))

## [1.0.10](https://github.com/postalsys/certs/compare/v1.0.9...v1.0.10) (2024-07-03)


### Bug Fixes

* bumped deps ([dcd7fda](https://github.com/postalsys/certs/commit/dcd7fda5769c9e1e35fc4f06ea403ff0cd8bdef7))

## [1.0.9](https://github.com/postalsys/certs/compare/v1.0.8...v1.0.9) (2024-04-12)


### Bug Fixes

* **deps:** Bumped deps ([ea7066a](https://github.com/postalsys/certs/commit/ea7066a6589672d4bdb55dadf706c89adef518fe))

## [1.0.8](https://github.com/postalsys/certs/compare/v1.0.7...v1.0.8) (2024-02-29)


### Bug Fixes

* **deps:** Bumped deps ([80cd271](https://github.com/postalsys/certs/commit/80cd2710c33c2d3975be8dfde3b8f3f0187f7ad0))

## [1.0.7](https://github.com/postalsys/certs/compare/v1.0.6...v1.0.7) (2023-10-31)


### Bug Fixes

* **deps:** Bumped deps ([38c5e25](https://github.com/postalsys/certs/commit/38c5e2537a1f63e8dd1c3529feecd78794dffde2))

## [1.0.6](https://github.com/postalsys/certs/compare/v1.0.5...v1.0.6) (2023-10-20)


### Bug Fixes

* **deploy:** Set up automatic deployment ([45ea1c7](https://github.com/postalsys/certs/commit/45ea1c71d8a4bf8fdbacefa38fa529022e68748e))
