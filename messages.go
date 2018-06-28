package dkg

// MessageType enum for dkg message (will likely change)
type MessageType int

// MessageType iota for dkg message (will likely change)
const (
	A MessageType = iota
)

// Message struct for dkg message (will likely change)
type Message struct {
	mType MessageType
}
