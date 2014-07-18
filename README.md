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

The `key.file` should contain the cipher key. For other options run with the `-h` flag :

```
Encrypt and decrypt files using an AES block cipher.

go-aes [ -d | -v | -vv ] [-mode mode] [-size size] key_file input_file output_file

  -d=false: whether in encryption mode
  -mode="ctr": block cipher mode, `ctr` for counter mode
  -size=128: cipher key size in bits, for encryption only
  -v=false: verbose output, debugging from block cipher mode
  -vv=false: very verbose output, includes debugging from block cipher

```

*Done mainly as a learning exercise by Emil Davtyan.*
