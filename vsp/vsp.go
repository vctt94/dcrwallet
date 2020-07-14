package vsp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"

	"decred.org/dcrwallet/wallet"
	"decred.org/dcrwallet/wallet/txauthor"
	"decred.org/dcrwallet/wallet/txsizes"
	"decred.org/dcrwallet/wallet/udb"
	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/blockchain/stake/v3"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/txscript/v3"
	"github.com/decred/dcrd/wire"
)

const (
	apiVSPInfo = "/api/vspinfo"

	serverSignature = "VSP-Server-Signature"
)

type VSP struct {
	hostname        string
	pubKey          ed25519.PublicKey
	httpClient      *http.Client
	params          *chaincfg.Params
	w               *wallet.Wallet
	purchaseAccount string
	changeAccount   string

	queueMtx sync.Mutex
	queue    chan *Queue

	outpoints map[chainhash.Hash][]udb.Credit
}

type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func New(ctx context.Context, hostname, pubKeyStr, purchaseAccount, changeAccount string, dialer DialFunc, w *wallet.Wallet, params *chaincfg.Params) (*VSP, error) {
	pubKey, err := hex.DecodeString(pubKeyStr)
	if err != nil {
		return nil, err
	}

	transport := http.Transport{
		DialContext: dialer,
	}
	httpClient := &http.Client{
		Transport: &transport,
	}

	v := &VSP{
		hostname:        hostname,
		pubKey:          ed25519.PublicKey(pubKey),
		httpClient:      httpClient,
		params:          params,
		w:               w,
		queue:           make(chan *Queue),
		purchaseAccount: purchaseAccount,
		changeAccount:   changeAccount,
		outpoints:       make(map[chainhash.Hash][]udb.Credit),
	}

	// Launch routine to process tickets.
	go func() {
		t := w.NtfnServer.TransactionNotifications()
		defer t.Done()
		r := w.NtfnServer.RemovedTransactionNotifications()
		defer r.Done()
		for {
			select {
			case <-ctx.Done():
				break
			case added := <-t.C:
				unmined := added.UnminedTransactionHashes
				go func() {
					for _, addedHash := range unmined {
						credits, exists := v.outpoints[*addedHash]
						if exists {
							for _, credit := range credits {
								w.UnlockOutpoint(credit.OutPoint)
								log.Infof("unlocked outpoint %v for added ticket %s",
									credit.OutPoint, addedHash)
							}
							delete(v.outpoints, *addedHash)
						}
					}
				}()
			case removed := <-r.C:
				txHash := removed.TxHash
				credits, exists := v.outpoints[txHash]
				if exists {
					go func() {
						for _, credit := range credits {
							w.UnlockOutpoint(credit.OutPoint)
							log.Infof("unlocked outpoint %v for deleted ticket %s",
								credit.OutPoint, txHash)
						}
					}()
				}
			case queuedItem := <-v.queue:
				err := v.Process(ctx, queuedItem)
				if err != nil {
					for _, credit := range queuedItem.Credits {
						w.UnlockOutpoint(credit.OutPoint)
					}
				}
			}
		}
		close(v.queue)
	}()

	return v, nil
}

func (v *VSP) PoolFee(ctx context.Context) (float64, error) {
	url := "https://" + v.hostname + apiVSPInfo

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Errorf("failed to create new fee address request: %v", err)
		return -1, err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		log.Errorf("vspinfo request failed: %v", err)
		return -1, err
	}
	// TODO - Add numBytes resp check

	responseBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Errorf("failed to read fee ddress response: %v", err)
		return -1, err
	}
	if resp.StatusCode != http.StatusOK {
		log.Warnf("vsp responded with an error: %v", string(responseBody))
		return -1, err
	}

	serverSigStr := resp.Header.Get(serverSignature)
	if serverSigStr == "" {
		log.Warnf("vspinfo response missing server signature")
		return -1, err
	}
	serverSig, err := hex.DecodeString(serverSigStr)
	if err != nil {
		log.Warnf("failed to decode server signature: %v", err)
		return -1, err
	}

	if !ed25519.Verify(v.pubKey, responseBody, serverSig) {
		log.Warnf("server failed verification")
		return -1, err
	}

	var vspInfo vspInfoResponse
	err = json.Unmarshal(responseBody, &vspInfo)
	if err != nil {
		log.Warnf("failed to unmarshal vspinfo response: %v", err)
		return -1, err
	}

	return vspInfo.FeePercentage, nil
}

func (v *VSP) TicketStatus(ctx context.Context, hash *chainhash.Hash) {
	url := "https://" + v.hostname + "/api/ticketstatus"

	ticketStatusRequest := TicketStatusRequest{
		Timestamp:  time.Now().Unix(),
		TicketHash: hash.String(),
	}

	requestBody, err := json.Marshal(&ticketStatusRequest)
	if err != nil {
		log.Errorf("failed to marshal ticket status request: %v", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, bytes.NewReader(requestBody))
	if err != nil {
		log.Errorf("failed to create new fee address request: %v", err)
		return
	}

	var commitmentAddr dcrutil.Address

	signature, err := v.w.SignMessage(ctx, string(requestBody), commitmentAddr)
	if err != nil {
		log.Errorf("failed to sign feeAddress request: %v", err)
		return
	}
	req.Header.Set("VSP-Client-Signature", base64.StdEncoding.EncodeToString(signature))

}

type Queue struct {
	TicketHash *chainhash.Hash
	Credits    []udb.Credit
}

func (v *VSP) Queue(ctx context.Context, ticketHash *chainhash.Hash, credits []udb.Credit) {
	queuedTicket := &Queue{
		TicketHash: ticketHash,
		Credits:    credits,
	}
	v.queue <- queuedTicket
}

func (v *VSP) Sync(ctx context.Context) {
	_, blockHeight := v.w.MainChainTip(ctx)

	startBlock := wallet.NewBlockIdentifierFromHeight(blockHeight - 4096)
	endBlock := wallet.NewBlockIdentifierFromHeight(blockHeight)

	f := func(ticketSummaries []*wallet.TicketSummary, _ *wire.BlockHeader) (bool, error) {
		for _, ticketSummary := range ticketSummaries {
			if ticketSummary.Status == wallet.TicketStatusLive ||
				ticketSummary.Status == wallet.TicketStatusImmature {

				v.Queue(ctx, ticketSummary.Ticket.Hash, nil)
			}
		}

		return false, nil
	}

	err := v.w.GetTickets(ctx, f, startBlock, endBlock)
	if err != nil {
		log.Errorf("failed to sync tickets: %v", err)
	}
}

type changeSource struct {
	script  []byte
	version uint16
}

func (c changeSource) Script() ([]byte, uint16, error) {
	return c.script, c.version, nil
}

func (c changeSource) ScriptSize() int {
	return len(c.script)
}

func (v *VSP) Process(ctx context.Context, queuedItem *Queue) error {
	hash := queuedItem.TicketHash
	credits := queuedItem.Credits

	txs, _, err := v.w.GetTransactionsByHashes(ctx, []*chainhash.Hash{hash})
	if err != nil {
		log.Errorf("failed to retrieve ticket %v: %v", hash, err)
		return err
	}
	ticketTx := txs[0]
	const scriptVersion = 0
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(scriptVersion,
		ticketTx.TxOut[0].PkScript, v.params)
	if err != nil {
		log.Errorf("failed to extract stake submission address from %v: %v", hash, err)
		return err
	}
	if len(addrs) == 0 {
		log.Errorf("failed to get address from %v", hash)
		return fmt.Errorf("failed to get address from %v", hash)
	}

	votingAddr := addrs[0]

	commitmentAddr, err := stake.AddrFromSStxPkScrCommitment(ticketTx.TxOut[1].PkScript, v.params)
	if err != nil {
		log.Errorf("failed to extract script addr from %v: %v", hash, err)
		return err
	}

	txBuf := new(bytes.Buffer)
	txBuf.Grow(ticketTx.SerializeSize())
	err = ticketTx.Serialize(txBuf)
	if err != nil {
		log.Errorf("failed to serialize ticket %v: %v", hash.String(), err)
		return err
	}

	feeAddressRequest := FeeAddressRequest{
		Timestamp:  time.Now().Unix(),
		TicketHash: hash.String(),
		TicketHex:  hex.EncodeToString(txBuf.Bytes()),
	}

	url := "https://" + v.hostname + "/api/feeaddress"

	requestBody, err := json.Marshal(feeAddressRequest)
	if err != nil {
		log.Errorf("failed to marshal fee address request: %v", err)
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(requestBody))
	if err != nil {
		log.Errorf("failed to create new fee address request: %v", err)
		return err
	}

	signature, err := v.w.SignMessage(ctx, string(requestBody), commitmentAddr)
	if err != nil {
		log.Errorf("failed to sign feeAddress request: %v", err)
		return err
	}
	req.Header.Set("VSP-Client-Signature", base64.StdEncoding.EncodeToString(signature))

	resp, err := v.httpClient.Do(req)
	if err != nil {
		log.Errorf("fee address request failed: %v", err)
		return err
	}
	// TODO - Add numBytes resp check

	responseBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Errorf("failed to read fee ddress response: %v", err)
		return err
	}
	if resp.StatusCode != http.StatusOK {
		log.Warnf("vsp responded with an error: %v", string(responseBody))
		return fmt.Errorf("vsp with an error (%v): %v", resp.StatusCode, string(responseBody))
	}

	serverSigStr := resp.Header.Get(serverSignature)
	if serverSigStr == "" {
		log.Warnf("feeaddress missing server signature")
		return fmt.Errorf("server signature missing from feeaddress response")
	}
	serverSig, err := hex.DecodeString(serverSigStr)
	if err != nil {
		log.Warnf("failed to decode server signature: %v", err)
		return err
	}

	if !ed25519.Verify(v.pubKey, responseBody, serverSig) {
		log.Warnf("server failed verification")
		return fmt.Errorf("server failed verification")
	}

	var feeResponse feeAddressResponse
	err = json.Unmarshal(responseBody, &feeResponse)
	if err != nil {
		log.Warnf("failed to unmarshal feeaddress response: %v", err)
		return err
	}

	// verify initial request matches server
	serverRequestBody, err := json.Marshal(feeResponse.Request)
	if err != nil {
		log.Warnf("failed to marshal response request: %v", err)
		return err
	}
	if !bytes.Equal(requestBody, serverRequestBody) {
		log.Warnf("server response has differing request: %#v != %#v",
			requestBody, serverRequestBody)
		return fmt.Errorf("server response contains differing request")
	}

	// TODO - validate server timestamp?

	// validate fee address
	feeAddress, err := dcrutil.DecodeAddress(feeResponse.FeeAddress, v.params)
	if err != nil {
		log.Warnf("unable to parse server fee address: %v", err)
		return err
	}
	feeAmount := dcrutil.Amount(feeResponse.FeeAmount)

	// TODO - convert 10 to vsp.maxfee config option
	maxFee, err := dcrutil.NewAmount(0.1)
	if err != nil {
		return err
	}

	if feeAmount > maxFee {
		log.Warnf("fee amount too high: %v > %v", feeAmount, maxFee)
		return fmt.Errorf("server fee amount too high: %v > %v", feeAmount, maxFee)
	}

	// TODO - remove "default"
	accountNum, err := v.w.AccountNumber(ctx, v.purchaseAccount)
	if err != nil {
		log.Warnf("failed to get account number: %v", err)
		return err
	}

	pkScript, err := txscript.PayToAddrScript(feeAddress)
	if err != nil {
		log.Warnf("failed to generate pay to addr script for %v: %v", feeAddress, err)
		return err
	}

	txOut := []*wire.TxOut{
		{
			Value:    int64(feeAmount),
			Version:  0,
			PkScript: pkScript,
		},
	}

	changeAcct, err := v.w.AccountNumber(ctx, v.changeAccount)
	if err != nil {
		log.Warnf("failed to account number for 'change': %v", err)
		return err
	}

	a, err := v.w.NewChangeAddress(ctx, changeAcct)
	if err != nil {
		log.Warnf("failed to get new change address: %v", err)
		return err
	}

	c, ok := a.(wallet.Address)
	if !ok {
		log.Warnf("failed to convert '%T' to wallet.Address", a)
		return fmt.Errorf("failed to convert '%T' to wallet.Address", a)
	}

	cver, cscript := c.PaymentScript()

	cs := changeSource{
		script:  cscript,
		version: cver,
	}

	var inputSource txauthor.InputSource
	if len(credits) > 0 {
		inputSource = func(amount dcrutil.Amount) (*txauthor.InputDetail, error) {
			if amount < 0 {
				return nil, fmt.Errorf("invalid amount: %d < 0", amount)
			}

			var detail txauthor.InputDetail
			if amount == 0 {
				return &detail, nil
			}

			for _, credit := range credits {
				if detail.Amount >= amount {
					break
				}

				log.Infof("credit: %v", credit.String())
				log.Infof("credit pkscript: %x", credit.PkScript)
				log.Infof("credit amount: %v", credit.Amount)
				log.Infof("credit: %v", spew.Sdump(credit))

				// TODO: copied from txauthor.MakeInputSource - make a shared function?
				// Unspent credits are currently expected to be either P2PKH or
				// P2PK, P2PKH/P2SH nested in a revocation/stakechange/vote output.
				var scriptSize int
				scriptClass := txscript.GetScriptClass(0, credit.PkScript)
				switch scriptClass {
				case txscript.PubKeyHashTy:
					scriptSize = txsizes.RedeemP2PKHSigScriptSize
				case txscript.PubKeyTy:
					scriptSize = txsizes.RedeemP2PKSigScriptSize
				case txscript.StakeRevocationTy, txscript.StakeSubChangeTy,
					txscript.StakeGenTy:
					scriptClass, err = txscript.GetStakeOutSubclass(credit.PkScript)
					if err != nil {
						return nil, fmt.Errorf(
							"failed to extract nested script in stake output: %v",
							err)
					}

					// For stake transactions we expect P2PKH and P2SH script class
					// types only but ignore P2SH script type since it can pay
					// to any script which the wallet may not recognize.
					if scriptClass != txscript.PubKeyHashTy {
						log.Errorf("unexpected nested script class for credit: %v",
							scriptClass)
						continue
					}

					scriptSize = txsizes.RedeemP2PKHSigScriptSize
				default:
					log.Errorf("unexpected script class for credit: %v",
						scriptClass)
					continue
				}

				inputs := wire.NewTxIn(&credit.OutPoint, int64(credit.Amount), credit.PkScript)

				detail.Amount += credit.Amount
				detail.Inputs = append(detail.Inputs, inputs)
				detail.Scripts = append(detail.Scripts, credit.PkScript)
				detail.RedeemScriptSizes = append(detail.RedeemScriptSizes, scriptSize)
			}
			return &detail, nil
		}
	}

	feeTx, err := v.w.NewUnsignedTransaction(ctx, txOut, v.w.RelayFee(), accountNum, 6,
		wallet.OutputSelectionAlgorithmDefault, cs, inputSource)
	if err != nil {
		log.Warnf("failed to create fee transaction: %v", err)
		return err
	}
	if feeTx.ChangeIndex >= 0 {
		feeTx.RandomizeChangePosition()
	}

	sigErrs, err := v.w.SignTransaction(ctx, feeTx.Tx, txscript.SigHashAll, nil, nil, nil)
	if err != nil {
		log.Errorf("failed to sign transaction: %v", err)
		for _, sigErr := range sigErrs {
			log.Errorf("\t%v", sigErr)
		}
		return err
	}
	txBuf.Reset()
	txBuf.Grow(feeTx.Tx.SerializeSize())
	err = feeTx.Tx.Serialize(txBuf)
	if err != nil {
		log.Errorf("failed to serialize fee transaction: %v", err)
		return err
	}

	votingKeyWIF, err := v.w.DumpWIFPrivateKey(ctx, votingAddr)
	if err != nil {
		log.Errorf("failed to retrieve privkey for %v in %v: %v", votingAddr, hash, err)
		return err
	}

	// PayFee
	voteChoices := make(map[string]string)
	voteChoices[chaincfg.VoteIDHeaderCommitments] = "yes"

	payRequest := PayFeeRequest{
		Timestamp:   time.Now().Unix(),
		TicketHash:  hash.String(),
		FeeTx:       hex.EncodeToString(txBuf.Bytes()),
		VotingKey:   votingKeyWIF,
		VoteChoices: voteChoices,
	}

	url = "https://" + v.hostname + "/api/payfee"

	requestBody, err = json.Marshal(payRequest)
	if err != nil {
		log.Errorf("failed to marshal pay request: %v", err)
		return err
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(requestBody))
	if err != nil {
		log.Errorf("failed to create new http requeust: %v", err)
		return err
	}
	signature, err = v.w.SignMessage(ctx, string(requestBody), commitmentAddr)
	if err != nil {
		log.Errorf("failed to sign feeAddress request: %v", err)
		return err
	}
	req.Header.Set("VSP-Client-Signature", base64.StdEncoding.EncodeToString(signature))

	resp, err = v.httpClient.Do(req)
	if err != nil {
		log.Errorf("payfee request failed: %v", err)
		return err
	}
	serverSigStr = resp.Header.Get(serverSignature)
	if serverSigStr == "" {
		log.Warnf("pay fee response missing server signature")
		return err
	}
	serverSig, err = hex.DecodeString(serverSigStr)
	if err != nil {
		log.Warnf("failed to decode server signature: %v", err)
		return err
	}

	// TODO - Add numBytes resp check
	responseBody, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Errorf("failed to read response body: %v", err)
		return err
	}
	if resp.StatusCode != http.StatusOK {
		log.Warnf("vsp responded with an error: %v", string(responseBody))
		return fmt.Errorf("vsp responded with an error (%v): %v", resp.StatusCode, string(responseBody))
	}

	if !ed25519.Verify(v.pubKey, responseBody, serverSig) {
		log.Warnf("server failed verification")
		return fmt.Errorf("server failed verification")
	}

	log.Infof("successfully processed %v", hash)

	return nil
}
