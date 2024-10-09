# go-wallet-sdk

[![License](https://img.shields.io/npm/l/@okxweb3/coin-base.svg)](https://github.com/okx/go-wallet-sdk/blob/main/LICENSE)

This is a Go language wallet solution that supports offline transactions. We currently support various mainstream public
blockchains, and will gradually release the source codes for each blockchain.

## Features

- Multi-chain support
- Offline transaction signing
- Account generation and management
- Customizable transaction creation
- BRC20/Atomical/Runes.. support for Bitcoin
- Extensible architecture

## Supported chains

|          | Account Generation | Transaction Creation | Transaction Signing |
|----------|-------------------|----------------------|---------------------|
| BTC      | ✅                 | ✅                    | ✅                   | 
| Ethereum | ✅                 | ✅                    | ✅                   |
| EOS      | ✅                 | ✅                    | ✅                   |
| Filecoin | ✅                 | ✅                    | ✅                   |
| Polkadot | ✅                 | ✅                    | ✅                   |
| Starknet | ✅                 | ✅                    | ✅                   |
| Aptos    | ✅                 | ✅                    | ✅                   |
| Near     | ✅                 | ✅                    | ✅                   |
| Solana   | ✅                 | ✅                    | ✅                   |
| Stacks   | ✅                 | ✅                    | ✅                   |
| SUI      | ✅                 | ✅                    | ✅                   |
| Tron     | ✅                 | ✅                    | ✅                   |
| Cosmos   | ✅                 | ✅                    | ✅                   |
| Axelar   | ✅                 | ✅                    | ✅                   |
| Cronos   | ✅                 | ✅                    | ✅                   |
| Evmos    | ✅                 | ✅                    | ✅                   |
| Iris     | ✅                 | ✅                    | ✅                   |
| Juno     | ✅                 | ✅                    | ✅                   |
| Kava     | ✅                 | ✅                    | ✅                   |
| Kujira   | ✅                 | ✅                    | ✅                   |
| Okc      | ✅                 | ✅                    | ✅                   |
| Osmosis  | ✅                 | ✅                    | ✅                   |
| Secret   | ✅                 | ✅                    | ✅                   |
| Sei      | ✅                 | ✅                    | ✅                   |
| Stargaze | ✅                 | ✅                    | ✅                   |
| Terra    | ✅                 | ✅                    | ✅                   |
| Tia      | ✅                 | ✅                    | ✅                   |
| Avax     | ✅                 | ✅                    | ✅                   |
| Elrond   | ✅                 | ✅                    | ✅                   |
| Flow     | ✅                 | ✅                    | ✅                   |
| Harmony  | ✅                 | ✅                    | ✅                   |
| Helium   | ✅                 | ✅                    | ✅                   |
| Kaspa    | ✅                 | ✅                    | ✅                   |
| Nervos   | ✅                 | ✅                    | ✅                   |
| Oasis    | ✅                 | ✅                    | ✅                   |
| Tezos    | ✅                 | ✅                    | ✅                   |
| Waves    | ✅                 | ✅                    | ✅                   |
| Zil      | ✅                 | ✅                    | ✅                   |
| Zkspace  | ✅                 | ✅                    | ✅                   |
| Zksync   | ✅                 | ✅                    | ✅                   |

*BTC: Supports Supports BRC20-related functions, including inscription creation, BRC20 buying and selling.

## Main modules

- coins: Implements transaction creation and signature in each coin type.
- crypto: Handles general security and signature algorithms.
- util: Provides various utility class methods.


## Installation
To use the OKX Web3 Wallet SDK, install the core packages and the specific coin packages you need:

```shell
# Core packages (required for all coins)
go get -u github.com/okx/go-wallet-sdk/crypto

# coin-specific packages (install as needed)

go get -u github.com/okx/go-wallet-sdk/coins/bitcoin

# ... other coin packages
```


## Usage

Here's a basic example of how to use the SDK with Ethereum:

```golang
package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/okx/go-wallet-sdk/coins/ethereum"
	"github.com/okx/go-wallet-sdk/crypto/bip32"
	"github.com/okx/go-wallet-sdk/util"
	"github.com/tyler-smith/go-bip39"
	btcec2 "github.com/btcsuite/btcd/btcec/v2"
	"math/big"
)

func main() {
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		panic(err)
	}
	fmt.Println(mnemonic)
	// get derived key
	hdPath := GetDerivedPath(0)
	derivePrivateKey, err := GetDerivedPrivateKey(mnemonic, hdPath)
	fmt.Println("generate derived private key:", derivePrivateKey, ",derived path: ", hdPath)

	// get new address
	newAddress := GetNewAddress(derivePrivateKey)
	fmt.Println("generate new address:", newAddress)
	// Sign a transaction
	txJson := `{
				"chainId":"11155111",
				"txType":2,
				"nonce":"1",
				"isToken":false,
				"to":"0x31c514837ee0f6062eaffb0882d764170a178004",
				"value":"21000",
				"gasLimit":"21000",
				"gasPrice":"66799178286",
				"maxFeePerGas":"20000000000",
				"maxPriorityFeePerGas":"1500000000"
			}`
	//02a501a1622ecdbdca2ff9ae36dfcf58603006e8fd5ddd4809e8b8b9b8a4cf9f8b
	signedTx, err := SignTransaction(txJson, derivePrivateKey)
	fmt.Println("signed tx:", signedTx)
}

func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	return mnemonic, err
}

func GetDerivedPath(index int) string {
	return fmt.Sprintf(`m/44'/60'/0'/0/%d`, index)
}

func GetDerivedPrivateKey(mnemonic string, hdPath string) (string, error) {
	seed := bip39.NewSeed(mnemonic, "")
	rp, err := bip32.NewMasterKey(seed)
	if err != nil {
		return "", err
	}
	c, err := rp.NewChildKeyByPathString(hdPath)
	if err != nil {
		return "", err
	}
	childPrivateKey := hex.EncodeToString(c.Key.Key)
	return childPrivateKey, nil
}

func GetNewAddress(prvHex string) string {
	prvBytes, err := hex.DecodeString(prvHex)
	if err != nil {
		return ""
	}
	prv, pub := btcec.PrivKeyFromBytes(btcec.S256(), prvBytes)
	if prv == nil {
		return ""
	}
	return ethereum.GetAddress(hex.EncodeToString(pub.SerializeCompressed()))
}

type SignParams struct {
	Type                 int    `json:"type"`
	ChainId              string `json:"chainId"`
	Nonce                string `json:"nonce"`
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
	MaxFeePerGas         string `json:"maxFeePerGas"`
	GasLimit             string `json:"gasLimit"`
	To                   string `json:"to"`
	Value                string `json:"value"`
	Data                 string `json:"data"`
	isToken              bool   `json:"isToken"`
}

func SignTransaction(txJson, prvHex string) (string, error) {
	if len(txJson) == 0 {
		return "", errors.New("invalid txJson")
	}
	if len(prvHex) == 0 {
		return "", errors.New("invalid prvHex")
	}
	var err error
	var s SignParams
	if err := json.Unmarshal([]byte(txJson), &s); err != nil {
		return "", err
	}
	chainId := util.ConvertToBigInt(s.ChainId)
	var to *common.Address
	if len(s.To) != 0 {
		addr := common.HexToAddress(s.To)
		to = &addr
	}
	var data []byte
	if len(s.Data) != 0 {
		if data, err = util.DecodeHexString(s.Data); err != nil {
			return "", err
		}
	}
	prvBytes, err := hex.DecodeString(prvHex)
	if err != nil {
		return "", errors.New("invalid prvHex")
	}
	var jsonTx ethereum.Eip1559Token
	if err := json.Unmarshal([]byte(txJson), &jsonTx); err != nil {
		return "", err
	}
	if jsonTx.TxType == types.DynamicFeeTxType { // EIP1559 sign
		prv, _ := btcec.PrivKeyFromBytes(btcec.S256(), prvBytes)
		tx := ethereum.NewEip1559Transaction(
			chainId,
			util.ConvertToBigInt(jsonTx.Nonce).Uint64(),
			util.ConvertToBigInt(jsonTx.MaxPriorityFeePerGas),
			util.ConvertToBigInt(jsonTx.MaxFeePerGas),
			util.ConvertToBigInt(jsonTx.GasLimit).Uint64(),
			to,
			util.ConvertToBigInt(jsonTx.Value),
			data,
		)
		res, hash, err := SignEip1559Transaction(chainId, tx, (*ecdsa.PrivateKey)(prv))
		if err != nil {
			return "", err
		}
		return toJson(SignedTx{Hash: hash, Hex: util.EncodeHexWith0x(res)}), nil
	} else {
		prv, _ := btcec2.PrivKeyFromBytes(prvBytes)
		// Token processing
		var tx *ethereum.EthTransaction
		if s.isToken {
			tx = ethereum.NewEthTransaction(util.ConvertToBigInt(jsonTx.Nonce), util.ConvertToBigInt(jsonTx.GasLimit), util.ConvertToBigInt(jsonTx.GasPrice), big.NewInt(0), jsonTx.ContractAddress, util.EncodeHexWith0x(data))
		} else {
			tx = ethereum.NewEthTransaction(util.ConvertToBigInt(jsonTx.Nonce), util.ConvertToBigInt(jsonTx.GasLimit), util.ConvertToBigInt(jsonTx.GasPrice), util.ConvertToBigInt(jsonTx.Value), jsonTx.To, util.EncodeHexWith0x(data))
		}
		res, err := tx.SignTransaction(chainId, (*secp256k1.PrivateKey)(prv))
		if err != nil {
			return "", err
		}
		return toJson(SignedTx{Hash: ethereum.CalTxHash(res), Hex: res}), nil
	}
}

type SignedTx struct {
	Hash string `json:"hash"`
	Hex  string `json:"hex"`
}

func toJson(r interface{}) string {
	res, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return string(res)
}

func SignEip1559Transaction(chainId *big.Int, tx *types.Transaction, prvKey *ecdsa.PrivateKey) ([]byte, string, error) {
	signer := types.NewLondonSigner(chainId)
	signedTx, err := types.SignTx(tx, signer, prvKey)
	if err != nil {
		return nil, "", err
	}
	rawTx, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, "", err
	}
	return rawTx, signedTx.Hash().Hex(), nil
}
```

For more detailed examples and usage instructions for each supported blockchain, please refer to the documentation in the respective coin-specific package.


## Example

For specific usage examples of each coin type, please refer to the corresponding test files. Remember to replace the
placeholder private key with your own private key, which is generally in hex format.

## Feedback and Support

You can provide feedback directly in GitHub Issues, and we will respond promptly.


## Security

If you find security risks, it is recommended to feedback through the following channels and get your reward!
submit on HackerOne platform https://hackerone.com/okg Or on our OKX feedback submission page > security bugs https://www.okx.com/feedback/submit


## License
Most packages or folder are [MIT](<https://github.com/okx/go-wallet-sdk/blob/main/LICENSE>) licensed, see package or folder for the respective license.
