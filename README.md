# dkg
[Distributed key generation](https://en.wikipedia.org/wiki/Distributed_key_generation)

This repository is a work in progress. It contains an implementation of [ECDKG by Tang](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.124.4128&rep=rep1&type=pdf) using the group interface from [dedis/kyber](https://github.com/dedis/kyber). This integration allows different elliptic curves such as [Secp256k1](https://github.com/ethereum/go-ethereum/tree/master/crypto/secp256k1) (with [tests](https://github.com/gnosis/dkg/blob/secp256k1/dkg_test.go)) and [bn256](github.com/dedis/kyber/pairing/bn256) (on master) to be used in the dkg scheme. 

## Installation
```go
go get https://github.com/gnosis/dkg
```

Take a look at the test for intended use. 

*Please Note:
The messaging/network layer of the scheme has not been implemented. 