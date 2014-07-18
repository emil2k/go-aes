# Go AES
[![Build Status](https://travis-ci.org/emil2k/go-aes.svg)](https://travis-ci.org/emil2k/go-aes)
[![Coverage Status](https://img.shields.io/coveralls/emil2k/go-aes.svg)](https://coveralls.io/r/emil2k/go-aes)

A Go implementation of the AES encryption standard. It can process 128 bit blocks with 128, 192, 256 bit cipher keys.

---

With `go install` will build a `go-aes` executable which can be used to encrypt :

```
go-aes key.file input.file output.aes
```
or decrypt :

```
go-aes -d key.file input.aes output.file
```

The `key.file` stores the cipher key.

*Done mainly as a learning a exercise by Emil Davtyan.*
