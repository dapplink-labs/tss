package types

import (
	tss "github.com/eniac-x-labs/tss/common"
	"github.com/eniac-x-labs/tss/index"
)

type SignService interface {
	SignStateBatch(request tss.SignStateRequest) ([]byte, error)
	SignRollBack(request tss.SignStateRequest) ([]byte, error)
	SignTxBatch() error
}

type AdminService interface {
	ResetScanHeight(height uint64) error
	GetScannedHeight() (uint64, error)
}

type TssQueryService interface {
	QueryActiveInfo() (*TssCommitteeInfo, error)
	QueryInactiveInfo() (*TssCommitteeInfo, error)
	QueryTssGroupMembers() (*TssCommitteeInfo, error)
}

type CPKStore interface {
	Insert(CpkData) error
	GetByElectionId(uint64) (CpkData, error)
}

type ManagerStore interface {
	CPKStore
	index.StateBatchStore
	index.ScanHeightStore
}
