package signer

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	// DefaultTimeout is default duration the service will wait on startup to
	// make a connection to either the L1 or L2 backends.
	DefaultTimeout = 5 * time.Second
)

// DialL2EthClientWithTimeout attempts to dial the L2 provider using the
// provided URL. If the dial doesn't complete within dial.DefaultTimeout seconds,
// this method will return an error.
func DialL2EthClientWithTimeout(ctx context.Context, url string, disableHTTP2 bool) (
	*ethclient.Client, error) {

	ctxt, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	if strings.HasPrefix(url, "http") {
		httpClient := new(http.Client)
		if disableHTTP2 {
			log.Info("Disabled HTTP/2 support in L2 eth client")
			httpClient.Transport = &http.Transport{
				TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			}
		}

		rpcClient, err := rpc.DialHTTPWithClient(url, httpClient)
		if err != nil {
			return nil, err
		}

		return ethclient.NewClient(rpcClient), nil
	}

	return ethclient.DialContext(ctxt, url)
}
