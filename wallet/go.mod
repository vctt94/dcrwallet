module github.com/decred/dcrwallet/wallet/v2

require (
	github.com/decred/dcrd/blockchain v1.1.1
	github.com/decred/dcrd/blockchain/stake v1.1.0
	github.com/decred/dcrd/chaincfg v1.3.0
	github.com/decred/dcrd/chaincfg/chainhash v1.0.1
	github.com/decred/dcrd/dcrec v0.0.0-20190214012338-9265b4051009
	github.com/decred/dcrd/dcrec/secp256k1 v1.0.1
	github.com/decred/dcrd/dcrjson/v2 v2.0.0
	github.com/decred/dcrd/dcrutil v1.2.0
	github.com/decred/dcrd/gcs v1.0.2
	github.com/decred/dcrd/hdkeychain v1.1.1
	github.com/decred/dcrd/mempool/v2 v2.0.0
	github.com/decred/dcrd/rpcclient/v2 v2.0.0
	github.com/decred/dcrd/txscript v1.0.2
	github.com/decred/dcrd/wire v1.2.0
	github.com/decred/dcrwallet/deployments v1.1.0
	github.com/decred/dcrwallet/errors v1.0.1
	github.com/decred/dcrwallet/internal/helpers v1.0.1
	github.com/decred/dcrwallet/internal/zero v1.0.1
	github.com/decred/dcrwallet/rpc/jsonrpc/types v1.0.0
	github.com/decred/dcrwallet/validate v1.0.2
	github.com/decred/slog v1.0.0
	github.com/jrick/bitset v1.0.0
	go.etcd.io/bbolt v1.3.2
	golang.org/x/crypto v0.0.0-20190211182817-74369b46fc67
	golang.org/x/sync v0.0.0-20181221193216-37e7f081c4d4
)

replace github.com/decred/dcrwallet/internal/helpers => ../internal/helpers
