package readprivacyabi

import "strings"

// ParticipantSlots is the finite established Explorer participation vocabulary.
// It is evaluated only after the consumer has qualified the actual event ABI.
func ParticipantSlots(topic0 string) []int {
	return append([]int{}, participantEventSlots[strings.ToLower(topic0)]...)
}

// ParticipantCatalog returns detached legacy-compatible data.
func ParticipantCatalog() map[string][]int {
	out := make(map[string][]int, len(participantEventSlots))
	for k, v := range participantEventSlots {
		out[k] = append([]int{}, v...)
	}
	return out
}

var participantEventSlots = map[string][]int{
	"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": {1, 2},    // Transfer
	"0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925": {1, 2},    // Approval
	"0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31": {1, 2},    // ApprovalForAll
	"0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62": {1, 2, 3}, // TransferSingle
	"0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb": {1, 2, 3}, // TransferBatch
	"0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c": {1},       // Deposit (WETH)
	"0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65": {1},       // Withdrawal (WETH)
}
