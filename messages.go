package dkg

type MessageType int

const (
	A MessageType = iota
)

type Message struct {
	mType MessageType
}
