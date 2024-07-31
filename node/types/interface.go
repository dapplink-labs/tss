package types

import (
	"github.com/eniac-x-labs/tss/index"
)

type TssMemberStore interface {
	SetInactiveMembers(TssMembers) error
	GetInactiveMembers() (TssMembers, error)
	SetActiveMembers(TssMembers) error
	GetActiveMembers() (TssMembers, error)
}

type NodeStore interface {
	index.StateBatchStore
	index.ScanHeightStore
	TssMemberStore
}
