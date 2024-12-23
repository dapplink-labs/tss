package signer

import (
	"time"

	"github.com/ethereum/go-ethereum/log"

	"github.com/eniac-x-labs/tss/node/types"
)

func (p *Processor) ObserveTssGroup() {
	queryTicker := time.NewTicker(p.taskInterval)
	for {
		log.Info("updating tss group member info")
		func() {
			tssInfo, err := p.tssQueryService.QueryInactiveInfo()
			if err != nil {
				log.Error("failed to query inactive info", "err", err)
				return
			} else {
				log.Info("query inactive members", "numbers", len(tssInfo.TssMembers))
				if len(tssInfo.TssMembers) > 0 {
					err := p.nodeStore.SetInactiveMembers(types.TssMembers{
						TssMembers: tssInfo.TssMembers,
					})
					if err != nil {
						log.Error("failed to set inactive members ", "err", err)
					}
				}
			}
			tssmembers, err := p.tssQueryService.QueryTssGroupMembers()
			if err != nil {
				log.Error("failed to query inactive info", "err", err)
				return
			} else {
				log.Info("query active members", "numbers", len(tssmembers.TssMembers))
				if len(tssmembers.TssMembers) > 0 {
					err := p.nodeStore.SetActiveMembers(types.TssMembers{
						TssMembers: tssmembers.TssMembers,
					})
					if err != nil {
						log.Error("failed to set active members ", "err", err)
					}
				}
			}
		}()

		select {
		case <-p.stopChan:
			return
		case <-queryTicker.C:
		}
	}
}
