package tssnode

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/ethereum/go-ethereum/crypto"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	tss "github.com/eniac-x-labs/tss/common"
	"github.com/eniac-x-labs/tss/index"
	"github.com/eniac-x-labs/tss/node/server"
	sign "github.com/eniac-x-labs/tss/node/signer"
	"github.com/eniac-x-labs/tss/node/store"
	"github.com/eniac-x-labs/tss/node/tsslib"
	"github.com/eniac-x-labs/tss/node/tsslib/common"
	"github.com/eniac-x-labs/tss/node/tsslib/conversion"
)

func Command() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "node",
		Short: "launch a tss node process",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runNode(cmd)
		},
	}
	cmd.Flags().BoolP("debug", "d", false, "log level,default info")
	return cmd
}

func runNode(cmd *cobra.Command) error {
	nonProd, _ := cmd.Flags().GetBool("non-prod")
	waitPeersFullConnected, _ := cmd.Flags().GetBool("full")
	debug, _ := cmd.Flags().GetBool("debug")

	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	cfg := tss.GetConfigFromCmd(cmd)

	if len(cfg.Node.PrivateKey) == 0 {
		return errors.New("need to config private key")
	}

	privKey, err := crypto.HexToECDSA(cfg.Node.PrivateKey)
	if err != nil {
		return err
	}

	//new level db storage
	store, err := store.NewStorage(cfg.Node.DBDir)
	if err != nil {
		return err
	}
	l1StartBlockNumber, err := strconv.ParseUint(
		cfg.L1StartBlockNumber, 10, 32,
	)
	if err != nil {
		return err
	}

	observer, err := index.NewIndexer(store, cfg.L1Url, cfg.L1ConfirmBlocks, cfg.TimedTaskInterval, l1StartBlockNumber)
	if err != nil {
		return err
	}
	observer.Start()

	//new tss server instance
	p2pPort, err := strconv.Atoi(cfg.Node.P2PPort)
	if err != nil {
		log.Error().Err(err).Msg("p2p port value in config file, can not convert to int type")
		return err
	}

	tssInstance, err := tsslib.NewTss(
		cfg.Node.BootstrapPeers,
		waitPeersFullConnected,
		p2pPort,
		privKey,
		cfg.Node.BaseDir,
		common.TssConfig{
			PreParamTimeout: cfg.Node.PreParamTimeout,
			KeyGenTimeout:   cfg.Node.KeyGenTimeout,
			KeySignTimeout:  cfg.Node.KeySignTimeout,
			EnableMonitor:   false,
		},
		cfg.Node.PreParamFile,
		cfg.Node.ExternalIP,
		cfg.Node.Secrets.Enable,
		cfg.Node.Secrets.SecretId,
		cfg.Node.Shamir,
		store,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("fail to create tss server instance")
		return err
	}
	if err := tssInstance.Start(); err != nil {
		log.Error().Err(err).Msg("fail to start tss server")
		return err
	}

	pubkey := crypto.CompressPubkey(&privKey.PublicKey)
	pubkeyHex := hex.EncodeToString(pubkey)

	localPubkeyBytes := crypto.FromECDSAPub(&privKey.PublicKey)
	// bytes len is 64
	localPubkeyBytes = localPubkeyBytes[1:]

	address := ethcrypto.PubkeyToAddress(privKey.PublicKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signer, err := sign.NewProcessor(cfg, ctx, tssInstance, privKey, localPubkeyBytes, pubkeyHex, store, address)
	if err != nil {
		log.Error().Err(err).Msg("fail to new signer ")
		return err
	}
	signer.Start()

	hs, err := server.NewHttpServer(cfg.Node.HttpAddr, tssInstance, signer, nonProd, cfg.Node.JwtSecret)
	if err != nil {
		log.Error().Err(err).Msg("fail to create http server")
		return err
	}

	if err := hs.Start(); err != nil {
		log.Error().Err(err).Msg("fail to start http server")
		return err
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info().Msg("stop signal received ")

	tssInstance.Stop()
	signer.Stop()
	hs.Stop()
	log.Info().Msg("server stopped")

	return nil
}

func PeerIDCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "parse-peer-id",
		Short: "parse peer id of the key",
		RunE: func(cmd *cobra.Command, args []string) error {
			publicKey, _ := cmd.Flags().GetString("pub-key")
			privateKey, _ := cmd.Flags().GetString("pri-key")
			var publicBz []byte
			if len(publicKey) != 0 {
				decoded, err := hex.DecodeString(publicKey)
				if err != nil {
					return err
				}
				publicBz = decoded
			} else if len(privateKey) != 0 {
				privKey, err := crypto.HexToECDSA(privateKey)
				if err != nil {
					return err
				}
				pubkeybytes := crypto.CompressPubkey(&privKey.PublicKey)
				publicBz = pubkeybytes
			} else {
				return errors.New("name|pub-key|pri-key at least one needs to be specified")
			}

			peerId, err := conversion.GetPeerIDFromSecp256PubKey(publicBz)
			if err != nil {
				return err
			}
			fmt.Println(peerId)

			return nil
		},
	}
	cmd.Flags().String("pub-key", "", "hex-encoded Ethereum public key with prefix")
	cmd.Flags().String("pri-key", "", "hex-encoded Ethereum private key")
	return cmd
}
