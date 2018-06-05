# Messages Specification
Messages in the protocol need to accomplish the following:
1. Key Distribution:
    1. Send secret shares `sx and sy` from server to player
    2. Broadcast public info `Pk` to all players
2. Key Verification:
    1. Broadcast player complaint against `pj`
    2. Broadcast `pj`'s shares to all if valid complaint
3. Key Check:
4. Key Generation:
    1. Broadcast public keys out

```go
struct SecretSharesMessage {
    from     *big.Int // or whatever the player id type is
    to       *big.Int
    s1x, s1y *big.Int
    s2x, s2y *big.Int
}

var network bytes.Buffer        // Stand-in for a network connection
	enc := gob.NewEncoder(&network) // Will write to network.
	dec := gob.NewDecoder(&network) // Will read from network.

	// Encode (send) some values.
	var msg = SecretSharesMessage{new big.Int(1), new big.Int(2), ... }
    err := enc.Encode(msg)
    var received SecretSharesMessage
    enc.Decode(&received)
```
