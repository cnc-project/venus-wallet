module github.com/filecoin-project/venus-wallet

go 1.16

require (
	contrib.go.opencensus.io/exporter/jaeger v0.2.1
	github.com/BurntSushi/toml v0.3.1
	github.com/ahmetb/go-linq/v3 v3.2.0
	github.com/asaskevich/EventBus v0.0.0-20200907212545-49d423059eef
	github.com/filecoin-project/go-address v0.0.5
	github.com/filecoin-project/go-cbor-util v0.0.0-20201016124514-d0bbec7bfcc4
	github.com/filecoin-project/go-crypto v0.0.0-20191218222705-effae4ea9f03
	github.com/filecoin-project/go-fil-markets v1.1.9
	github.com/filecoin-project/go-jsonrpc v0.1.4-0.20210217175800-45ea43ac2bec
	github.com/filecoin-project/go-state-types v0.1.1-0.20210506134452-99b279731c48
	github.com/filecoin-project/specs-actors v0.9.14
	github.com/filecoin-project/specs-actors/v2 v2.3.5
	github.com/filecoin-project/specs-actors/v3 v3.1.1
	github.com/filecoin-project/specs-actors/v4 v4.0.1
	github.com/filecoin-project/specs-actors/v5 v5.0.1
	github.com/fsnotify/fsnotify v1.4.9
	github.com/fxamacker/cbor/v2 v2.3.0
	github.com/gbrlsnchs/jwt/v3 v3.0.0
	github.com/google/uuid v1.2.0
	github.com/howeyc/gopass v0.0.0-20190910152052-7cb4b85ec19c
	github.com/ipfs-force-community/venus-common-utils v0.0.0-20210714054928-2042a9040759
	github.com/ipfs-force-community/venus-gateway v1.1.2-0.20210731031356-770f19abfbcb
	github.com/ipfs/go-block-format v0.0.3
	github.com/ipfs/go-cid v0.0.7
	github.com/ipfs/go-ipld-cbor v0.0.5
	github.com/ipfs/go-log/v2 v2.3.0
	github.com/minio/blake2b-simd v0.0.0-20160723061019-3f5f724cb5b1
	github.com/mitchellh/go-homedir v1.1.0
	github.com/multiformats/go-multiaddr v0.3.3
	github.com/prometheus/common v0.26.0
	github.com/spf13/cast v1.3.1
	github.com/spf13/viper v1.7.1
	github.com/supranational/blst v0.3.4
	github.com/urfave/cli/v2 v2.3.0
	github.com/whyrusleeping/cbor-gen v0.0.0-20210219115102-f37d292932f2
	go.opencensus.io v0.23.0
	go.uber.org/fx v1.9.0
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	gorm.io/driver/sqlite v1.1.4
	gorm.io/gorm v1.21.12
	gotest.tools v2.2.0+incompatible
)

replace github.com/ipfs/go-ipfs-cmds => github.com/ipfs-force-community/go-ipfs-cmds v0.6.1-0.20210521090123-4587df7fa0ab

replace github.com/filecoin-project/go-jsonrpc => github.com/ipfs-force-community/go-jsonrpc v0.1.4-0.20210731021807-68e5207079bc
