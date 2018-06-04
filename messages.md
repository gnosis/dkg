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

Message types:
```
Distribution
Verification
Generation
```
```
Struct {
    _mType         MessageType
    id             *big.Int //message id
    sx             *big.Int //s_ij
    sy             *big.Int //s'_ij
    P              *big.Int //P_ik
    A              *big.Int //A_i0
    i              int      //player
    j              int      //server
    complaint      bool
    complaintValid bool
    private        bool
}
```