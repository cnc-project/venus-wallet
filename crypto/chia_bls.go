package crypto

import (
	cb "github.com/cnc-project/cnc-bls"
	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/venus-wallet/core"
	"golang.org/x/xerrors"
)

type blsChiaPrivate struct {
	key      cb.PrivateKey
	public   cb.PublicKey
	mnemonic string
}

func genChiaBlsPrivate(password string) (PrivateKey, error) {
	entropy, _ := cb.NewEntropy()
	mnemonic, _ := cb.NewMnemonic(entropy)
	// Note private keys seem to be serialized big-endian!
	pk := cb.KeyGen(cb.NewSeed(mnemonic, password))
	return &blsChiaPrivate{
		key:      pk,
		public:   pk.GetPublicKey(),
		mnemonic: mnemonic,
	}, nil
}

// notes ：Forget the mnemonic words can be imported in this way, but the mnemonic words will not be deduced based on private
func newChiaBlsKeyFromData(data []byte, mnemonic string) PrivateKey {
	if cb.CheckMnemonic(mnemonic) {
		pk ,_ := genChiaBlsWithMnemonic(mnemonic,"")
		return pk
	}

	pk := cb.KeyFromBytes(data)
	return &blsChiaPrivate{
		key:      pk,
		public:   pk.GetPublicKey(),
		mnemonic: mnemonic,
	}
}

// generate privateKey based on mnemonic
func genChiaBlsWithMnemonic(mnemonic, password string) (PrivateKey, error) {
	pk := cb.KeyGenWithMnemonic(mnemonic, password)
	return &blsChiaPrivate{
		key:      pk,
		public:   pk.GetPublicKey(),
		mnemonic: mnemonic,
	}, nil
}

func (b *blsChiaPrivate) Public() []byte {
	return b.public.Bytes()
}

func (b *blsChiaPrivate) Sign(bytes []byte) (*core.Signature, error) {
	return &core.Signature{
		Type: b.Type(),
		Data: new(cb.AugSchemeMPL).Sign(b.key, bytes),
	}, nil
}

func (b *blsChiaPrivate) Bytes() []byte {
	return b.key.Bytes()
}

func (b *blsChiaPrivate) Address() (core.Address, error) {
	addr, err := address.NewBLSAddress(b.public.Bytes())
	if err != nil {
		return core.NilAddress, xerrors.Errorf("converting BLS to address: %w", err)
	}
	return addr, nil
}

func (b *blsChiaPrivate) Type() core.SigType {
	return core.SigTypeChiaBLS
}

func (b *blsChiaPrivate) KeyType() core.KeyType {
	return core.KTCBLS
}

func (b *blsChiaPrivate) ToKeyInfo() *core.KeyInfo {
	return &core.KeyInfo{
		PrivateKey: b.Bytes(),
		Type:       core.KTCBLS,
		Mnemonic:   b.mnemonic,
	}
}

func (b *blsChiaPrivate) GetMnemonic() string {
	return b.mnemonic
}

// pk []byte,  msg Message, sig []byte
func blsChiaVerify(sig []byte, a core.Address, msg []byte) error {
	pk, err := cb.NewPublicKey(a.Payload()[:])
	if err != nil {
		return err
	}

	if !new(cb.AugSchemeMPL).Verify(pk, msg, sig) {
		return xerrors.New("bls signature failed to verify")
	}
	return nil
}
