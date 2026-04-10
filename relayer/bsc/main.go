// BSC -> 自定义链 单向 Wormhole Relayer
// 流程: 轮询 guardian REST API 拿 VAA → 提交到目标链合约的 receiveMessage(bytes)
package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

var (
	guardianURL    = flag.String("guardian", "http://47.236.70.29:9000", "Guardian REST API base URL")
	targetRPC      = flag.String("rpc", "wss://bsc-testnet-rpc.publicnode.com", "")
	targetContract = flag.String("contract", "0x85eCf0B4B642E6907E68e236da82F5fCd8dDc04F", "目标链合约地址 (required)")
	privateKeyHex  = flag.String("key", "388cc540b319852a0d299df60d4965d817fc3fdb2701b2d1e108d091cb0f70d9", "提交交易的私钥 hex (required)")
	emitterChain   = flag.Uint("emitter-chain", 4, "源链 chain ID (4=BSC)")
	emitterAddr    = flag.String("emitter-addr", "0xE63540Dad30d48e2e65D511379D070CbD5A38CF6", "源链 emitter 合约地址 (required)")
	startSeq       = flag.Uint64("start-seq", 14, "从哪个 sequence 开始")
	pollInterval   = flag.Duration("interval", 5*time.Second, "轮询间隔")
)

// 目标合约需要实现: receiveMessage(bytes encodedVM)
const receiveMessageABI = `[{
	"inputs":[{"internalType":"bytes","name":"encodedVM","type":"bytes"}],
	"name":"receiveMessage",
	"outputs":[],
	"stateMutability":"nonpayable",
	"type":"function"
}]`

func main() {
	flag.Parse()

	if *targetRPC == "" || *targetContract == "" || *privateKeyHex == "" || *emitterAddr == "" {
		flag.Usage()
		log.Fatal("missing required flags: -rpc -contract -key -emitter-addr")
	}

	emitter := normalizeEmitter(*emitterAddr)
	log.Printf("Relayer started | guardian=%s chain=%d emitter=%s startSeq=%d",
		*guardianURL, *emitterChain, emitter, *startSeq)

	client, err := ethclient.Dial(*targetRPC)
	if err != nil {
		log.Fatalf("connect target chain: %v", err)
	}
	defer client.Close()

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		log.Fatalf("get chain id: %v", err)
	}
	log.Printf("Target chain ID: %s", chainID)

	pk, err := crypto.HexToECDSA(strings.TrimPrefix(*privateKeyHex, "0x"))
	if err != nil {
		log.Fatalf("invalid private key: %v", err)
	}

	parsedABI, err := abi.JSON(strings.NewReader(receiveMessageABI))
	if err != nil {
		log.Fatalf("parse ABI: %v", err)
	}

	contractAddr := common.HexToAddress(*targetContract)
	seq := *startSeq

	for {
		vaaBytes, err := fetchVAA(*guardianURL, uint32(*emitterChain), emitter, seq)
		if err != nil {
			fmt.Println(err)
			log.Printf("[seq=%d] not ready: %v", seq, err)
			time.Sleep(*pollInterval)
			continue
		}

		log.Printf("[seq=%d] VAA fetched (%d bytes), submitting...", seq, len(vaaBytes))

		submitVAA(client, pk, chainID, parsedABI, contractAddr, vaaBytes)
		//if err != nil {
		//	log.Printf("[seq=%d] submit failed: %v", seq, err)
		//	time.Sleep(*pollInterval)
		//	continue
		//}

		//log.Printf("[seq=%d] submitted tx=%s", seq, txHash)
		seq++
	}
}

// fetchVAA 从 guardian REST API 拉取 VAA
func fetchVAA(baseURL string, chain uint32, emitter string, seq uint64) ([]byte, error) {
	url := fmt.Sprintf("%s/v1/signed_vaa/%d/%s/%d", baseURL, chain, emitter, seq)
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("VAA not yet available")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}

	var result struct {
		VaaBytes string `json:"vaaBytes"` // base64
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	return base64.StdEncoding.DecodeString(result.VaaBytes)
}

// submitVAA 调用目标链合约 receiveMessage(bytes)
func submitVAA(
	client *ethclient.Client,
	pk *ecdsa.PrivateKey,
	chainID *big.Int,
	parsedABI abi.ABI,
	contractAddr common.Address,
	vaaBytes []byte,
) (string, error) {
	ctx := context.Background()
	from := crypto.PubkeyToAddress(pk.PublicKey)

	data, err := parsedABI.Pack("receiveMessage", vaaBytes)
	if err != nil {
		return "", fmt.Errorf("pack: %w", err)
	}

	nonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}

	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return "", fmt.Errorf("gas price: %w", err)
	}

	gasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{
		From: from,
		To:   &contractAddr,
		Data: data,
	})
	if err != nil {
		log.Printf("gas estimate failed (%v), using 300000", err)
		gasLimit = 300000
	}

	tx := types.NewTransaction(nonce, contractAddr, big.NewInt(0), gasLimit, gasPrice, data)

	signedTx, err := types.SignTx(tx, types.NewLondonSigner(chainID), pk)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	if err := client.SendTransaction(ctx, signedTx); err != nil {
		return "", fmt.Errorf("send: %w", err)
	}
	fmt.Println(signedTx.Hash().Hex())

	return signedTx.Hash().Hex(), nil
}

// normalizeEmitter 将 EVM 地址规范化为 64 位 hex（32字节）
func normalizeEmitter(addr string) string {
	addr = strings.TrimPrefix(addr, "0x")
	addr = strings.ToLower(addr)
	if len(addr) == 40 {
		return strings.Repeat("0", 24) + addr
	}
	return addr
}
