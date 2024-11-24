package index

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
)

const scanRange = 10

type Indexer struct {
	store              IndexerStore
	l1Cli              *ethclient.Client
	l1ConfirmBlocks    int
	l1StartBlockNumber uint64
	taskInterval       time.Duration
	stopChan           chan struct{}
}

func NewIndexer(store IndexerStore, l1url string, l1ConfirmBlocks int, taskInterval string, l1StartBlockNumber uint64) (Indexer, error) {
	taskIntervalDur, err := time.ParseDuration(taskInterval)
	if err != nil {
		return Indexer{}, nil
	}
	l1Cli, err := ethclient.Dial(l1url)
	if err != nil {
		return Indexer{}, err
	}
	return Indexer{
		store:              store,
		l1Cli:              l1Cli,
		l1ConfirmBlocks:    l1ConfirmBlocks,
		l1StartBlockNumber: l1StartBlockNumber,
		taskInterval:       taskIntervalDur,
		stopChan:           make(chan struct{}),
	}, nil
}

func (o Indexer) Start() {
	scannedHeight, err := o.store.GetScannedHeight()
	if err != nil {
		panic(err)
	}
	if scannedHeight < o.l1StartBlockNumber {
		scannedHeight = o.l1StartBlockNumber
	}
	log.Info("start to observe MessageHashAppended event", "start_height", scannedHeight)
	go o.ObserveMessageHashAppended(scannedHeight)
}

func (o Indexer) Stop() {
	close(o.stopChan)
}

func (o Indexer) ObserveMessageHashAppended(scannedHeight uint64) {
	queryTicker := time.NewTicker(o.taskInterval)
	for {
		func() {
			currentHeader, err := o.l1Cli.HeaderByNumber(context.Background(), nil)
			if err != nil {
				log.Error("failed to call layer1 HeaderByNumber", err)
				return
			}
			latestConfirmedBlockHeight := currentHeader.Number.Uint64() - uint64(o.l1ConfirmBlocks)

			startHeight := scannedHeight + 1
			endHeight := startHeight + scanRange
			if latestConfirmedBlockHeight < endHeight {
				endHeight = latestConfirmedBlockHeight
			}
			if startHeight > endHeight {
				log.Info("Waiting for L1 block produced", "latest confirmed height", latestConfirmedBlockHeight)
				return
			}

			scannedHeight = endHeight
			retry := true
			for retry { // retry until update successfully
				if err = o.store.UpdateHeight(scannedHeight); err != nil {
					log.Error("failed to update scannedHeight, retry", err)
					time.Sleep(2 * time.Second)
					retry = true
				} else {
					retry = false
				}
				log.Info("updated height", "scannedHeight", scannedHeight)
			}
		}()

		select {
		case <-o.stopChan:
			return
		case <-queryTicker.C:
		}

	}
}
