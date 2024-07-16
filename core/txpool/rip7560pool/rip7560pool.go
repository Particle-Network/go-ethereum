package rip7560pool

import (
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
)

type Config struct {
	MaxBundleSize uint
	MaxBundleGas  uint
}

// RIP7560Pool is the transaction pool dedicated to RIP-7560 AA transactions.
// This implementation relies on an external bundler process to perform most of the hard work.
type RIP7560Pool struct {
	config      Config
	chain       legacypool.BlockChain
	txFeed      event.Feed
	currentHead atomic.Pointer[types.Header] // Current head of the blockchain

	pending    []*types.Transaction
	pendingMap map[common.Hash]*types.Transaction
	included   map[common.Hash]*types.Receipt

	mu sync.Mutex

	coinbase common.Address
}

func (pool *RIP7560Pool) Type() uint64 {
	return 3
}

func (pool *RIP7560Pool) Init(_ uint64, head *types.Header, _ txpool.AddressReserver) error {
	pool.pending = make([]*types.Transaction, 0)
	pool.pendingMap = make(map[common.Hash]*types.Transaction)
	pool.included = make(map[common.Hash]*types.Receipt)
	pool.currentHead.Store(head)
	return nil
}

func (pool *RIP7560Pool) Close() error {
	return nil
}

func (pool *RIP7560Pool) Reset(oldHead, newHead *types.Header) {

}

// SetGasTip is ignored by the External Bundler AA sub pool.
func (pool *RIP7560Pool) SetGasTip(_ *big.Int) {}

func (pool *RIP7560Pool) Has(hash common.Hash) bool {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	tx := pool.Get(hash)
	return tx != nil
}

func (pool *RIP7560Pool) Get(hash common.Hash) *types.Transaction {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for _, tx := range pool.pending {
		if tx.Hash().Cmp(hash) == 0 {
			return tx
		}
	}
	return nil
}

// func (pool *RIP7560Pool) Add(_ []*types.Transaction, _ bool, _ bool) []error {
// 	return nil
// }

func (pool *RIP7560Pool) Pending(_ txpool.PendingFilter) map[common.Address][]*txpool.LazyTransaction {
	return nil
}

// SubscribeTransactions is not needed for the External Bundler AA sub pool and 'ch' will never be sent anything.
func (pool *RIP7560Pool) SubscribeTransactions(ch chan<- core.NewTxsEvent, _ bool) event.Subscription {
	return pool.txFeed.Subscribe(ch)
}

// Nonce is only used from 'GetPoolNonce' which is not relevant for AA transactions.
func (pool *RIP7560Pool) Nonce(_ common.Address) uint64 {
	return 0
}

// Stats function not implemented for the External Bundler AA sub pool.
func (pool *RIP7560Pool) Stats() (int, int) {
	return 0, 0
}

// Content function not implemented for the External Bundler AA sub pool.
func (pool *RIP7560Pool) Content() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	return nil, nil
}

// ContentFrom function not implemented for the External Bundler AA sub pool.
func (pool *RIP7560Pool) ContentFrom(_ common.Address) ([]*types.Transaction, []*types.Transaction) {
	return nil, nil
}

// Locals are not necessary for AA Pool
func (pool *RIP7560Pool) Locals() []common.Address {
	return []common.Address{}
}

func (pool *RIP7560Pool) Status(hash common.Hash) txpool.TxStatus {
	panic("not")
}

// New creates a new RIP-7560 Account Abstraction Bundler transaction pool.
func New(config Config, chain legacypool.BlockChain, coinbase common.Address) *RIP7560Pool {
	return &RIP7560Pool{
		config:   config,
		chain:    chain,
		coinbase: coinbase,
	}
}

// Filter rejects all individual transactions for External Bundler AA sub pool.
func (pool *RIP7560Pool) Filter(tx *types.Transaction) bool {
	return tx.Type() == types.RIP7560TxType
}

func (pool *RIP7560Pool) Add(txs []*types.Transaction, _ bool, _ bool) []error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	log.Warn("RIP7560Pool Add", "count", len(txs))

	var errs []error

	pool.pending = append(pool.pending, txs...)

	pool.txFeed.Send(core.NewTxsEvent{Txs: txs})

	return errs
}
