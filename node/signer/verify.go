package signer

import (
	"encoding/hex"
	"encoding/json"
	"sync"

	tdtypes "github.com/tendermint/tendermint/rpc/jsonrpc/types"

	"github.com/eniac-x-labs/tss/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func (p *Processor) Verify() {
	defer p.wg.Done()
	logger := p.logger.With().Str("step", "verify event").Logger()
	logger.Info().Msg("start to verify events ")

	go func() {
		defer func() {
			logger.Info().Msg("exit verify event process")
		}()
		for {
			select {
			case <-p.stopChan:
				return
			case req := <-p.askRequestChan:
				var askRequest common.TransactionSignRequest
				var RpcResponse tdtypes.RPCResponse
				if err := json.Unmarshal(req.Params, &askRequest); err != nil {
					logger.Error().Msg("failed to unmarshal ask request")
					RpcResponse = tdtypes.NewRPCErrorResponse(req.ID, 201, "failed to unmarshal ", err.Error())
					if err := p.wsClient.SendMsg(RpcResponse); err != nil {
						logger.Error().Err(err).Msg("failed to send msg to manager")
					}
					continue
				}
				if askRequest.MessageHash == "" {
					logger.Error().Msg("StartBlock and OffsetStartsAtIndex must not be nil or negative")
					RpcResponse = tdtypes.NewRPCErrorResponse(req.ID, 201, "invalid askRequest", "StartBlock and OffsetStartsAtIndex must not be nil or negative")
					if err := p.wsClient.SendMsg(RpcResponse); err != nil {
						logger.Error().Err(err).Msg("failed to send msg to manager")
					}
					return
				}
				var resId = req.ID
				var size = len(askRequest.MessageHash)
				logger.Info().Msgf("stateroots size %d ", size)
				if len(askRequest.MessageHash) == 0 {
					logger.Error().Msg("stateroots size is empty")
					RpcResponse = tdtypes.NewRPCErrorResponse(req.ID, 201, "stateroots size is empty ", "do not need to sign")
					if err := p.wsClient.SendMsg(RpcResponse); err != nil {
						logger.Error().Err(err).Msg("failed to send msg to manager")
					}
					continue
				} else {
					wg := &sync.WaitGroup{}
					wg.Add(1)

					hash, err := hex.DecodeString(askRequest.MessageHash)
					if err != nil {
						logger.Err(err).Msg("failed to conv msg to hash")
						RpcResponse = tdtypes.NewRPCErrorResponse(req.ID, 201, "failed to conv msg to hash", err.Error())
						if err := p.wsClient.SendMsg(RpcResponse); err != nil {
							logger.Error().Err(err).Msg("failed to send msg to manager")
						}
						continue
					} else {
						hashStr := hexutil.Encode(hash)
						p.UpdateWaitSignEvents(hashStr, askRequest)
					}

					askResponse := common.AskResponse{
						Result: true,
					}
					RpcResponse = tdtypes.NewRPCSuccessResponse(resId, askResponse)
					if err := p.wsClient.SendMsg(RpcResponse); err != nil {
						logger.Error().Err(err).Msg("failed to send msg to manager")
					}

				}
			}

		}
	}()
}

func (p *Processor) UpdateWaitSignEvents(uniqueId string, msg common.TransactionSignRequest) {
	p.waitSignLock.Lock()
	defer p.waitSignLock.Unlock()
	p.waitSignMsgs[uniqueId] = msg
}

func (p *Processor) CacheVerify(key string, value bool) bool {
	p.cacheVerifyLock.Lock()
	defer p.cacheVerifyLock.Unlock()
	return p.cacheVerify.Set(key, value)
}

func (p *Processor) GetVerify(key string) (bool, bool) {
	p.cacheVerifyLock.RLock()
	defer p.cacheVerifyLock.RUnlock()
	return p.cacheVerify.Get(key)
}
