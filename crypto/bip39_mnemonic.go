package crypto

import (
	"github.com/tyler-smith/go-bip39"
)

func NewEntropy() ([]byte, error) {
	return bip39.NewEntropy(256)
}

func NewMnemonic(entropy []byte) (string, error) {
	return bip39.NewMnemonic(entropy)
}

func NewSeed(mnemonic, password string) []byte {
	return bip39.NewSeed(mnemonic, password)
}

func CheckMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(mnemonic)
}

func MnemonicToEntropy(mnemonic string) []byte {
	key, _ := bip39.EntropyFromMnemonic(mnemonic)
	return key
}