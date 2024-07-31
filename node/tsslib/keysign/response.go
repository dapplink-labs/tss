package keysign

import (
	common2 "github.com/binance-chain/tss-lib/common"

	"github.com/eniac-x-labs/tss/node/tsslib/common"
)

type Response struct {
	SignatureData *common2.SignatureData `json:"signature_data"`
	Status        common.Status          `json:"status"`
	FailReason    string                 `json:"failReason"`
}

func NewResponse(signature *common2.SignatureData, status common.Status, failReason string) Response {
	return Response{
		SignatureData: signature,
		Status:        status,
		FailReason:    failReason,
	}
}
