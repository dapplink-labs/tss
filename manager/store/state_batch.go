package store

import (
	"encoding/hex"
	"encoding/json"

	"github.com/eniac-x-labs/tss/index"
)

func (s *Storage) SetMessageHash(info index.MessageHashInfo) error {
	bz, err := json.Marshal(info)
	if err != nil {
		return err
	}
	msgByte, _ := hex.DecodeString(info.MessageHash)
	return s.db.Put(msgByte, bz, nil)
}

func (s *Storage) GetMessageHash(root [32]byte) (bool, index.MessageHashInfo) {
	bz, err := s.db.Get(getMessageHashKey(root), nil)
	if err != nil {
		return handleError2(index.MessageHashInfo{}, err)
	}
	var sbi index.MessageHashInfo
	if err = json.Unmarshal(bz, &sbi); err != nil {
		return false, index.MessageHashInfo{}
	}
	return true, sbi
}

func (s *Storage) IndexMessageHash(index uint64, root [32]byte) error {
	return s.db.Put(getIndexMessageHashKey(index), root[:], nil)
}

func (s *Storage) GetIndexMessageHash(index uint64) (bool, [32]byte) {
	bz, err := s.db.Get(getIndexMessageHashKey(index), nil)
	if err != nil {
		return handleError2([32]byte{}, err)
	}
	var stateRoot [32]byte
	copy(stateRoot[:], bz)
	return true, stateRoot
}
