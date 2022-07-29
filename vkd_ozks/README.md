## vkd 

An implementation of an auditable key directory (also known as a verifiable registry).

Auditable key directories can be used to help provide key transparency for end-to-end encrypted
messaging.

This implementation is based off of the protocol described in
[SEEMless: Secure End-to-End Encrypted Messaging with less trust](https://eprint.iacr.org/2018/607).

This library provides a stateless API for an auditable key directory, meaning that a consumer of this library must provide their own solution for the storage of the entries of the directory.

⚠️ **Warning**: This implementation has not been audited and is not ready for a production application. Use at your own risk!

Documentation
-------------

The API can be found XXXX along with an example for usage.

Installation
------------

Add the following line to the dependencies of your `Cargo.toml`:

```
vkd = "0.4"
```

### Minimum Supported Rust Version

Rust **1.51** or higher.

Contributors
------------

The authors of this code are "Anon. authors of NDSS Submission #545"

License
-------

This project is licensed under either [Apache 2.0](https://github.com/submission_code_ndss_f2022_545/vkd_ozks/blob/main/LICENSE-APACHE) or [MIT](https://github.com/submission_code_ndss_f2022_545/vkd_ozks/blob/main/LICENSE-MIT), at your option.
