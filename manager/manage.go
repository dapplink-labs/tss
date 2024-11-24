package manager

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/influxdata/influxdb/pkg/slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"

	"github.com/eniac-x-labs/tss/bindings/tgm"
	tss "github.com/eniac-x-labs/tss/common"
	"github.com/eniac-x-labs/tss/index"
	"github.com/eniac-x-labs/tss/manager/metics"
	"github.com/eniac-x-labs/tss/manager/types"
	"github.com/eniac-x-labs/tss/ws/server"
)

type Manager struct {
	wsServer              server.IWebsocketManager
	tssQueryService       types.TssQueryService
	store                 types.ManagerStore
	l1Cli                 *ethclient.Client
	privateKey            *ecdsa.PrivateKey
	chainId               *big.Int
	tssGroupManagerCaller *tgm.TssGroupManagerCaller
	l1ConfirmBlocks       int

	taskInterval          time.Duration
	confirmReceiptTimeout time.Duration
	keygenTimeout         time.Duration
	cpkConfirmTimeout     time.Duration
	askTimeout            time.Duration
	signTimeout           time.Duration

	stateSignatureCache map[[32]byte][]byte
	sigCacheLock        *sync.RWMutex
	stopGenKey          bool
	stopChan            chan struct{}
	metics              *metics.Metrics
}

func NewManager(wsServer server.IWebsocketManager,
	tssQueryService types.TssQueryService,
	store types.ManagerStore,
	config tss.Configuration) (*Manager, error) {
	taskIntervalDur, err := time.ParseDuration(config.TimedTaskInterval)
	if err != nil {
		return nil, err
	}
	receiptConfirmTimeoutDur, err := time.ParseDuration(config.L1ReceiptConfirmTimeout)
	if err != nil {
		return nil, err
	}
	keygenTimeoutDur, err := time.ParseDuration(config.Manager.KeygenTimeout)
	if err != nil {
		return nil, err
	}
	cpkConfirmTimeoutDur, err := time.ParseDuration(config.Manager.CPKConfirmTimeout)
	if err != nil {
		return nil, err
	}
	askTimeoutDur, err := time.ParseDuration(config.Manager.AskTimeout)
	if err != nil {
		return nil, err
	}
	signTimeoutDur, err := time.ParseDuration(config.Manager.SignTimeout)
	if err != nil {
		return nil, err
	}

	l1Cli, err := ethclient.Dial(config.L1Url)
	if err != nil {
		return nil, err
	}

	tssGroupManagerCaller, err := tgm.NewTssGroupManagerCaller(common.HexToAddress(config.TssGroupContractAddress), l1Cli)
	if err != nil {
		return nil, err
	}
	privKey, err := crypto.HexToECDSA(config.Manager.PrivateKey)
	if err != nil {
		return nil, err
	}

	chainId, err := l1Cli.ChainID(context.Background())
	if err != nil {
		return nil, err
	}

	return &Manager{
		wsServer:        wsServer,
		tssQueryService: tssQueryService,
		store:           store,
		l1Cli:           l1Cli,
		l1ConfirmBlocks: config.L1ConfirmBlocks,

		tssGroupManagerCaller: tssGroupManagerCaller,
		privateKey:            privKey,
		chainId:               chainId,

		taskInterval:          taskIntervalDur,
		confirmReceiptTimeout: receiptConfirmTimeoutDur,
		keygenTimeout:         keygenTimeoutDur,
		cpkConfirmTimeout:     cpkConfirmTimeoutDur,
		askTimeout:            askTimeoutDur,
		signTimeout:           signTimeoutDur,

		stateSignatureCache: make(map[[32]byte][]byte),
		sigCacheLock:        &sync.RWMutex{},
		stopChan:            make(chan struct{}),
		metics:              metics.PrometheusMetrics("tssmanager"),
	}, nil
}

// Start launch a manager
func (m *Manager) Start() {
	log.Info("manager is starting......")
	go m.observeElection()
}

func (m *Manager) Stop() {
	close(m.stopChan)
}

func (m *Manager) stopGenerateKey() {
	m.stopGenKey = true
}

func (m *Manager) recoverGenerateKey() {
	m.stopGenKey = false
}

func (m *Manager) TransactionSign(request tss.TransactionSignRequest) ([]byte, error) {
	log.Info("received sign state request", "message hash", request.MessageHash)
	digestBz, err := hex.DecodeString(request.MessageHash)
	if err != nil {
		return nil, err
	}
	if sig := m.getStateSignature(digestBz); len(sig) > 0 {
		log.Info("get stored signature ", "digest", hex.EncodeToString(digestBz), "sig", hex.EncodeToString(sig))
		response := tss.BatchSubmitterResponse{
			Signature: sig,
		}
		responseBytes, err := json.Marshal(response)
		if err != nil {
			log.Error("batch submitter response failed to marshal !")
			return nil, err
		}
		return responseBytes, nil
	}

	tssInfo, err := m.tssQueryService.QueryActiveInfo()
	if err != nil {
		return nil, err
	}
	//metrics
	m.metics.ActiveMembersCount.Set(float64(len(tssInfo.TssMembers)))

	availableNodes := m.availableNodes(tssInfo.TssMembers)
	if len(availableNodes) < tssInfo.Threshold+1 {
		return nil, errors.New("not enough available nodes to sign state")
	}

	ctx := types.NewContext().
		WithAvailableNodes(availableNodes).
		WithTssInfo(tssInfo).
		WithRequestId(randomRequestId()).
		WithElectionId(tssInfo.ElectionId)

	// ask tss nodes for the agreement
	ctx, err = m.agreement(ctx, request, tss.AskMessageHash)
	if err != nil {
		m.metics.SignCount.Add(1)
		return nil, err
	}
	var resp tss.SignResponse
	var rollback bool
	var signErr error

	m.metics.ApproveNumber.Set(float64(len(ctx.Approvers())))

	request.ElectionId = tssInfo.ElectionId
	resp, signErr = m.sign(ctx, request, digestBz, tss.TransactionSign)

	if signErr != nil {
		m.metics.SignCount.Add(1)
		return nil, signErr
	}

	m.metics.SignCount.Set(0)

	if !rollback {
		absents := make([]string, 0)
		for _, node := range tssInfo.TssMembers {
			if !slices.ExistsIgnoreCase(ctx.Approvers(), node) {
				absents = append(absents, node)
			}
		}
		if err = m.afterTransactionSign(ctx, request.MessageHash, absents); err != nil {
			log.Error("failed to execute afterSign", "err", err)
		}

		m.setStateSignature(digestBz, resp.Signature)
		m.metics.RollbackCount.Set(0)
	} else {
		m.metics.RollbackCount.Add(1)
	}
	fmt.Println("=======================Signature====================================")
	fmt.Println(hex.EncodeToString(resp.Signature))
	fmt.Println("=======================Signature====================================")
	response := tss.BatchSubmitterResponse{
		Signature: resp.Signature,
	}
	responseBytes, err := json.Marshal(response)
	if err != nil {
		log.Error("batch submitter response failed to marshal !")
		return nil, err
	}
	return responseBytes, nil
}

func (m *Manager) SignTxBatch() error {
	return errors.New("not support for now")
}

func (m *Manager) availableNodes(tssMembers []string) []string {
	aliveNodes := m.wsServer.AliveNodes()
	m.metics.OnlineNodesCount.Set(float64(len(aliveNodes)))
	log.Info("check available nodes", "expected", fmt.Sprintf("%v", tssMembers), "alive nodes", fmt.Sprintf("%v", aliveNodes))

	availableNodes := make([]string, 0)
	for _, n := range aliveNodes {
		if slices.ExistsIgnoreCase(tssMembers, n) {
			availableNodes = append(availableNodes, n)
		}
	}
	return availableNodes
}

// current time + 4 digit random number
func randomRequestId() string {
	code := fmt.Sprintf("%04v", rand.New(rand.NewSource(time.Now().UnixNano())).Int31n(10000))
	return time.Now().Format("20060102150405") + code
}

func (m *Manager) afterTransactionSign(ctx types.Context, MessageHash string, absentNodes []string) error {
	sbi := index.MessageHashInfo{
		MessageHash:  MessageHash,
		ElectionId:   ctx.ElectionId(),
		AbsentNodes:  absentNodes,
		WorkingNodes: ctx.AvailableNodes(),
	}
	log.Info("Store the signed state batch", " messageHash", MessageHash)
	if err := m.store.SetMessageHash(sbi); err != nil {
		return err
	}
	return nil
}

func (m *Manager) getStateSignature(digestBz []byte) []byte {
	m.sigCacheLock.RLock()
	defer m.sigCacheLock.RUnlock()
	var key [32]byte
	copy(key[:], digestBz)
	return m.stateSignatureCache[key]
}

func (m *Manager) setStateSignature(digestBz []byte, sig []byte) {
	m.sigCacheLock.Lock()
	defer m.sigCacheLock.Unlock()
	for key := range m.stateSignatureCache {
		delete(m.stateSignatureCache, key)
	}
	var key [32]byte
	copy(key[:], digestBz)
	m.stateSignatureCache[key] = sig
}
