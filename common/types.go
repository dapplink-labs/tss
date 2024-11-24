package common

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type Method string

const (
	AskMessageHash  Method = "askMessageHash"
	TransactionSign Method = "TransactionSign"
	AskSlash        Method = "askSlash"
	SignSlash       Method = "signSlash"
	SignRollBack    Method = "signRollBack"
	AskRollBack     Method = "askRollBack"

	CulpritErrorCode = 100
)

func (m Method) String() string {
	return string(m)
}

type TransactionSignRequest struct {
	MessageHash string `json:"message_hash"`
	ElectionId  uint64 `json:"election_id"`
}

func (tsr TransactionSignRequest) String() string {
	return fmt.Sprintf("message_hash: %v, election_id: %d", tsr.MessageHash, tsr.ElectionId)
}

type SlashRequest struct {
	Address    common.Address `json:"address"`
	BatchIndex uint64         `json:"batch_index"`
	SignType   byte           `json:"sign_type"`
}

type RollBackRequest struct {
	StartBlock *big.Int `json:"start_block"`
}

type AskResponse struct {
	Result bool `json:"result"`
}

type NodeSignRequest struct {
	ClusterPublicKey string      `json:"cluster_public_key"`
	Timestamp        int64       `json:"timestamp"`
	Nodes            []string    `json:"nodes"`
	RequestBody      interface{} `json:"request_body"`
}

type SignResponse struct {
	Signature []byte `json:"signature"`
}

type KeygenRequest struct {
	Nodes      []string `json:"nodes"`
	ElectionId uint64   `json:"election_id"`
	Threshold  int      `json:"threshold"`
	Timestamp  int64    `json:"timestamp"`
}

type KeygenResponse struct {
	ClusterPublicKey string `json:"cluster_public_key"`
}

type SignatureData struct {
	SignatureRecovery []byte `json:"signature_recovery,omitempty"`
	R                 []byte `json:"r,omitempty"`
	S                 []byte `json:"s,omitempty"`
	M                 []byte `json:"m,omitempty"`
}

type BatchSubmitterResponse struct {
	Signature []byte `json:"signature"`
}
