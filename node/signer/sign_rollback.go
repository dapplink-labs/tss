package signer

import (
	"encoding/json"
	tsscommon "github.com/eniac-x-labs/tss/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	tdtypes "github.com/tendermint/tendermint/rpc/jsonrpc/types"
	"math/big"
)

func (p *Processor) SignRollBack() {
	defer p.wg.Done()
	logger := p.logger.With().Str("step", "sign Roll Back Message").Logger()

	logger.Info().Msg("start to sign roll back message ")

	go func() {
		defer func() {
			logger.Info().Msg("exit sign roll back process")
		}()
		for {
			select {
			case <-p.stopChan:
				return
			case req := <-p.signRollBackChan:
				var resId = req.ID.(tdtypes.JSONRPCStringID).String()
				logger.Info().Msgf("dealing resId (%s) ", resId)

				var nodeSignRequest tsscommon.NodeSignRequest
				rawMsg := json.RawMessage{}
				nodeSignRequest.RequestBody = &rawMsg

				if err := json.Unmarshal(req.Params, &nodeSignRequest); err != nil {
					logger.Error().Msg("failed to unmarshal roll back request")
					RpcResponse := tdtypes.NewRPCErrorResponse(req.ID, 201, "failed", err.Error())
					if err := p.wsClient.SendMsg(RpcResponse); err != nil {
						logger.Error().Err(err).Msg("failed to send msg to manager")
					}
					continue
				}
				var requestBody tsscommon.RollBackRequest
				if err := json.Unmarshal(rawMsg, &requestBody); err != nil {
					logger.Error().Msg("failed to umarshal roll back params request body")
					RpcResponse := tdtypes.NewRPCErrorResponse(req.ID, 201, "failed", err.Error())
					if err := p.wsClient.SendMsg(RpcResponse); err != nil {
						logger.Error().Err(err).Msg("failed to send msg to manager")
					}
					continue
				}
				if requestBody.StartBlock == nil ||
					requestBody.StartBlock.Cmp(big.NewInt(0)) < 0 {
					logger.Error().Msg("StartBlock must not be nil or negative")
					RpcResponse := tdtypes.NewRPCErrorResponse(req.ID, 201, "failed", "StartBlock must not be nil or negative")
					if err := p.wsClient.SendMsg(RpcResponse); err != nil {
						logger.Error().Err(err).Msg("failed to send msg to manager")
					}
					continue
				}
				nodeSignRequest.RequestBody = requestBody
				hashTx, err := tsscommon.RollBackHash(requestBody.StartBlock)
				if err != nil {
					logger.Err(err).Msg("failed to encode roll back msg")
					RpcResponse := tdtypes.NewRPCErrorResponse(req.ID, 201, "failed", err.Error())
					if err := p.wsClient.SendMsg(RpcResponse); err != nil {
						logger.Error().Err(err).Msg("failed to send msg to manager")
					}
					continue
				}

				var signResponse tsscommon.SignResponse

				hashStr := hexutil.Encode(hashTx)
				signByte, ok := p.GetSign(hashStr)
				if ok {
					logger.Info().Msg("singer get roll back signature from cache")
					signResponse = tsscommon.SignResponse{
						Signature: signByte,
					}
				} else {
					data, err := p.handleSign(nodeSignRequest, hashTx, logger)

					if err != nil {
						logger.Error().Msgf("roll back %s sign failed ", requestBody.StartBlock)
						var errorRes tdtypes.RPCResponse
						errorRes = tdtypes.NewRPCErrorResponse(req.ID, 201, "sign failed", err.Error())

						er := p.wsClient.SendMsg(errorRes)
						if er != nil {
							logger.Err(er).Msg("failed to send msg to tss manager")
						}
						continue
					}
					signResponse = tsscommon.SignResponse{
						Signature: data,
					}
					bol := p.CacheSign(hashStr, data)
					logger.Info().Msgf("cache roll back sign byte behavior %s ", bol)
				}

				RpcResponse := tdtypes.NewRPCSuccessResponse(req.ID, signResponse)
				err = p.wsClient.SendMsg(RpcResponse)
				if err != nil {
					logger.Err(err).Msg("failed to sendMsg to bridge ")
				} else {
					logger.Info().Msg("send roll back sign response successfully")
				}
			}
		}
	}()
}
