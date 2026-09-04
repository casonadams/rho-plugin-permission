# Changelog

## [0.2.0](https://github.com/casonadams/rho-plugin-permission/compare/v0.1.3...v0.2.0) (2026-09-04)


### Features

* align permission engine with pi extension feature parity ([7f4be32](https://github.com/casonadams/rho-plugin-permission/commit/7f4be325c2db99951056ee57751ccd843387066f))
* allow rho's built-in fd and rg tools by default with path surface checks ([eb85585](https://github.com/casonadams/rho-plugin-permission/commit/eb855854343f10459223eee4702eaa1ded5a6e26))
* always-allow drafts target the component that asked (path rules for path access) ([c507acb](https://github.com/casonadams/rho-plugin-permission/commit/c507acbd931a9eb85d412485bf5f611fd3ea4694))
* attach ; to the end of the statement line in multi-line command display ([4977455](https://github.com/casonadams/rho-plugin-permission/commit/4977455e4a6b5eb98c5a2e1651b5136f50e9cad3))
* inline input for Edit, Always allow, and Deny in the same menu via select input specs ([142f6cf](https://github.com/casonadams/rho-plugin-permission/commit/142f6cf5bcc1b155a462a5ec2b522be0fa78bac1))
* make permission menu a pure picker; deny reason moves to its own prompt ([89469c2](https://github.com/casonadams/rho-plugin-permission/commit/89469c27c323953d63c32817b6c813c5cf0a2389))
* name the rule surface in the always-allow input label and description ([2da23f7](https://github.com/casonadams/rho-plugin-permission/commit/2da23f78787dd2d4b6a18e87b91b235dea82fef9))
* path tools draft always-allow rules on the path surface scoped to the accessed path ([5faaf92](https://github.com/casonadams/rho-plugin-permission/commit/5faaf92693b3f625392c42d0976daebc07dc34d7))
* rename Edit / View to Edit and prefill the input buffer via SDK input_with_default ([c0520e8](https://github.com/casonadams/rho-plugin-permission/commit/c0520e89d00f5cb162ccb3041dde56e6762d600e))
* render compound bash commands multi-line in the permission prompt ([c0e5d44](https://github.com/casonadams/rho-plugin-permission/commit/c0e5d44e91548b041503728ae88cf4765382d8c7))


### Bug Fixes

* treat bare ~ as a path token in bash commands so ls ~ checks the path surface ([b1a8ed6](https://github.com/casonadams/rho-plugin-permission/commit/b1a8ed6a0594060256f1cb15fd468b7ce88d830d))


### Miscellaneous Chores

* lock rho-plugin-sdk 0.2.0 from crates.io ([a6c0951](https://github.com/casonadams/rho-plugin-permission/commit/a6c0951f92be35e9b9946fc31dcc9f749ba56ba7))

## [0.1.3](https://github.com/casonadams/rho-plugin-permission/compare/v0.1.2...v0.1.3) (2026-09-02)


### Features

* add rig-native json-rpc daemon mode supporting hook/tool_call and host/ui/select ([02d6cc1](https://github.com/casonadams/rho-plugin-permission/commit/02d6cc185e02bf137599454a94be7d5b6c6115ba))
* clarify permission denial message so model does not retry blocked commands ([0d8b93f](https://github.com/casonadams/rho-plugin-permission/commit/0d8b93fe89632693ba05ce3371a30ae95989d792))

## [0.1.2](https://github.com/casonadams/rho-plugin-permission/compare/v0.1.1...v0.1.2) (2026-09-02)


### Features

* permission plugin with rule matching, interactive prompt, and rule persistence ([a9ecdde](https://github.com/casonadams/rho-plugin-permission/commit/a9ecddef00c7bf66967b81b0fa933f91f4d059dd))
* **permission:** ask rules, workspace confinement, and deny-reason UX ([7c04875](https://github.com/casonadams/rho-plugin-permission/commit/7c0487520ad8579fc75349c4a6ba92acdc274806))


### Bug Fixes

* **release:** OIDC publish action, plain-binary assets, unprefixed tags ([215d981](https://github.com/casonadams/rho-plugin-permission/commit/215d9818a3832d5e79a04d80ca0de6cfb9f03989))

## [0.1.1](https://github.com/casonadams/rho-plugin-permission/compare/rho-plugin-permission-v0.1.0...rho-plugin-permission-v0.1.1) (2026-09-02)


### Features

* permission plugin with rule matching, interactive prompt, and rule persistence ([a9ecdde](https://github.com/casonadams/rho-plugin-permission/commit/a9ecddef00c7bf66967b81b0fa933f91f4d059dd))
* **permission:** ask rules, workspace confinement, and deny-reason UX ([7c04875](https://github.com/casonadams/rho-plugin-permission/commit/7c0487520ad8579fc75349c4a6ba92acdc274806))
