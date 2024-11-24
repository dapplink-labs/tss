package signer

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/btcsuite/btcd/btcec"
	"github.com/influxdata/influxdb/pkg/slices"
	"github.com/rs/zerolog"
	tdtypes "github.com/tendermint/tendermint/rpc/jsonrpc/types"
	"math/big"

	"github.com/ethereum/go-ethereum/common/hexutil"

	tsscommon "github.com/eniac-x-labs/tss/common"
	"github.com/eniac-x-labs/tss/index"
	"github.com/eniac-x-labs/tss/node/tsslib/common"
	"github.com/eniac-x-labs/tss/node/tsslib/keysign"
)

func (p *Processor) Sign() {
	defer p.wg.Done()
	logger := p.logger.With().Str("step", "sign Message").Logger()

	logger.Info().Msg("start to sign message ")

	go func() {
		defer func() {
			logger.Info().Msg("exit sign process")
		}()
		for {
			select {
			case <-p.stopChan:
				return
			case req := <-p.signRequestChan:
				var resId = req.ID.(tdtypes.JSONRPCStringID).String()
				logger.Info().Msgf("dealing resId (%s) ", resId)

				var nodeSignRequest tsscommon.NodeSignRequest
				rawMsg := json.RawMessage{}
				nodeSignRequest.RequestBody = &rawMsg

				if err := json.Unmarshal(req.Params, &nodeSignRequest); err != nil {
					logger.Error().Msg("failed to unmarshal ask request")
					RpcResponse := tdtypes.NewRPCErrorResponse(req.ID, 201, "failed", err.Error())
					if err := p.wsClient.SendMsg(RpcResponse); err != nil {
						logger.Error().Err(err).Msg("failed to send msg to manager")
					}
					continue
				}
				var requestBody tsscommon.TransactionSignRequest
				if err := json.Unmarshal(rawMsg, &requestBody); err != nil {
					logger.Error().Msg("failed to unmarshal asker's params request body")
					RpcResponse := tdtypes.NewRPCErrorResponse(req.ID, 201, "failed", err.Error())
					if err := p.wsClient.SendMsg(RpcResponse); err != nil {
						logger.Error().Err(err).Msg("failed to send msg to manager")
					}
					continue
				}
				if requestBody.MessageHash == "" {
					logger.Error().Msg("StartBlock and OffsetStartsAtIndex must not be nil or negative")
					RpcResponse := tdtypes.NewRPCErrorResponse(req.ID, 201, "failed", "StartBlock and OffsetStartsAtIndex must not be nil or negative")
					if err := p.wsClient.SendMsg(RpcResponse); err != nil {
						logger.Error().Err(err).Msg("failed to send msg to manager")
					}
					continue
				}
				nodeSignRequest.RequestBody = requestBody

				go p.SignGo(req.ID.(tdtypes.JSONRPCStringID), nodeSignRequest, logger)

			}
		}
	}()
}

func (p *Processor) SignGo(resId tdtypes.JSONRPCStringID, sign tsscommon.NodeSignRequest, logger zerolog.Logger) error {
	var data []byte
	requestBody := sign.RequestBody.(tsscommon.TransactionSignRequest)
	err, hash, signByte := p.checkMessages(requestBody)
	hashStr := hexutil.Encode(hash)

	if err != nil {
		RpcResponse := tdtypes.NewRPCErrorResponse(resId, 201, "failed", err.Error())

		if err := p.wsClient.SendMsg(RpcResponse); err != nil {
			logger.Error().Err(err).Msg("failed to send msg to manager")
		}
		logger.Err(err).Msg("check event failed")
		return err
	}

	//cache can not find the sign result by hashStr,we need to handle sign request.
	if signByte == nil {
		signData, err := p.handleSign(sign, hash, logger)
		if err != nil {
			logger.Error().Msgf(" %s sign failed ", hashStr)
			var errorRes tdtypes.RPCResponse
			errorRes = tdtypes.NewRPCErrorResponse(resId, 201, "sign failed", err.Error())

			er := p.wsClient.SendMsg(errorRes)
			if er != nil {
				logger.Err(er).Msg("failed to send msg to tss manager")
			}
			return err
		}
		bol := p.CacheSign(hashStr, signData)
		logger.Info().Msgf("cache sign byte behavior %s ", bol)
		data = signData
	} else {
		data = signByte
	}
	signResponse := tsscommon.SignResponse{
		Signature: data,
	}
	RpcResponse := tdtypes.NewRPCSuccessResponse(resId, signResponse)
	logger.Info().Msg("start to send response to manager ")

	err = p.wsClient.SendMsg(RpcResponse)
	if err != nil {
		logger.Err(err).Msg("failed to sendMsg to tss manager ")
		return err
	} else {
		logger.Info().Msg("send sign response to manager successfully")
		err := p.storeMessageHash(requestBody.ElectionId, requestBody.MessageHash, sign.Nodes, sign.ClusterPublicKey)
		if err != nil {
			logger.Err(err).Msg("failed to store MessageHash to level db")
		}
		p.removeWaitEvent(hashStr)
		return nil
	}

}

func (p *Processor) handleSign(sign tsscommon.NodeSignRequest, hashTx []byte, logger zerolog.Logger) ([]byte, error) {

	logger.Info().Msgf(" timestamp (%d) ,dealing sign hex (%s)", sign.Timestamp, hexutil.Encode(hashTx))

	signedData, err := p.sign(hashTx, sign.Nodes, sign.ClusterPublicKey, logger)
	if err != nil {
		return nil, err
	}
	signatureBytes := getSignatureBytes(&signedData)
	return signatureBytes, nil
}

func (p *Processor) sign(digestBz []byte, signerPubKeys []string, poolPubKey string, logger zerolog.Logger) (signatureData tsscommon.SignatureData, err error) {

	logger.Info().Str("message", hex.EncodeToString(digestBz)).Msg("got message to be signed")
	keysignReq := keysign.NewRequest(poolPubKey, digestBz, signerPubKeys)
	keysignRes, err := p.tssServer.KeySign(keysignReq)
	if err != nil {
		logger.Err(err).Msg("fail to generate signature ")
		return signatureData, err
	}
	if keysignRes.Status == common.Success {
		signatureData = tsscommon.SignatureData{
			SignatureRecovery: keysignRes.SignatureData.SignatureRecovery,
			R:                 keysignRes.SignatureData.R,
			S:                 keysignRes.SignatureData.S,
			M:                 keysignRes.SignatureData.M,
		}

		return signatureData, nil
	} else {
		return signatureData, errors.New(keysignRes.FailReason)
	}
}

func (p *Processor) checkMessages(sign tsscommon.TransactionSignRequest) (err error, hashByte, signByte []byte) {
	hashByte, err = hex.DecodeString(sign.MessageHash)
	if err != nil {
		return err, hashByte, nil
	}
	hashStr := hexutil.Encode(hashByte)

	signByte, ok := p.GetSign(hashStr)
	if ok {
		return nil, hashByte, signByte
	}

	p.waitSignLock.RLock()
	defer p.waitSignLock.RUnlock()
	_, ok = p.waitSignMsgs[hashStr]
	if !ok {
		return errors.New("sign request has the unverified state batch"), nil, nil
	}
	return nil, hashByte, nil
}

func (p *Processor) removeWaitEvent(key string) {
	p.waitSignLock.Lock()
	defer p.waitSignLock.Unlock()
	delete(p.waitSignMsgs, key)
}

func getSignatureBytes(sig *tsscommon.SignatureData) []byte {
	R := new(big.Int).SetBytes(sig.R)
	S := new(big.Int).SetBytes(sig.S)
	N := btcec.S256().N
	halfOrder := new(big.Int).Rsh(N, 1)
	if S.Cmp(halfOrder) == 1 {
		S.Sub(N, S)
	}
	rBytes := R.Bytes()
	sBytes := S.Bytes()
	cBytes := sig.SignatureRecovery

	sigBytes := make([]byte, 65)
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	copy(sigBytes[64:65], cBytes)
	return sigBytes
}

func (p *Processor) storeMessageHash(electionId uint64, messageHash string, workingNodes []string, poolPubkey string) error {
	paricipants, err := p.tssServer.GetParticipants(poolPubkey)
	if err != nil {
		return err
	}
	absentNodes := make([]string, 0)
	for _, n := range paricipants {
		if !slices.ExistsIgnoreCase(workingNodes, n) {
			absentNodes = append(absentNodes, n)
		}
	}

	sbi := index.MessageHashInfo{
		MessageHash:  messageHash,
		ElectionId:   electionId,
		AbsentNodes:  absentNodes,
		WorkingNodes: workingNodes,
	}
	if err = p.nodeStore.SetMessageHash(sbi); err != nil {
		return err
	}
	return nil
}

func (p *Processor) CacheSign(key string, value []byte) bool {
	p.cacheSignLock.Lock()
	defer p.cacheSignLock.Unlock()
	return p.cacheSign.Set(key, value)
}

func (p *Processor) GetSign(key string) ([]byte, bool) {
	p.cacheSignLock.RLock()
	defer p.cacheSignLock.RUnlock()
	return p.cacheSign.Get(key)
}
