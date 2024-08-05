package rip7560pool

import (
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
)

type Config struct {
	MaxPoolSize uint
}

// RIP7560Pool is the transaction pool dedicated to RIP-7560 AA transactions.
// This implementation relies on an external bundler process to perform most of the hard work.
type RIP7560Pool struct {
	config Config
	chain  legacypool.BlockChain
	txFeed event.Feed

	// currentHead atomic.Pointer[types.Header] // Current head of the blockchain
	// currentState  *state.StateDB             // Current state in the blockchain head

	pending    []*types.Transaction
	pendingMap map[common.Hash]*types.Transaction

	mu sync.RWMutex

	coinbase common.Address
}

func (pool *RIP7560Pool) Type() uint64 {
	return 3
}

func (pool *RIP7560Pool) Init(_ uint64, head *types.Header, _ txpool.AddressReserver) error {
	pool.pending = make([]*types.Transaction, 0)
	pool.pendingMap = make(map[common.Hash]*types.Transaction)

	// pool.currentHead.Store(head)
	return nil
}

func (pool *RIP7560Pool) Close() error {
	log.Info("RIP7560 Transaction pool stopped")
	return nil
}

func (pool *RIP7560Pool) Reset(oldHead, newHead *types.Header) {
}

// SetGasTip is ignored by the External Bundler AA sub pool.
func (pool *RIP7560Pool) SetGasTip(_ *big.Int) {}

func (pool *RIP7560Pool) Has(hash common.Hash) bool {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// tx := pool.Get(hash)
	_, ok := pool.pendingMap[hash]
	return ok
}

func (pool *RIP7560Pool) Get(hash common.Hash) *types.Transaction {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// for _, tx := range pool.pending {
	// 	if tx.Hash().Cmp(hash) == 0 {
	// 		return tx
	// 	}
	// }
	return pool.pendingMap[hash]
}

func (pool *RIP7560Pool) Pending(filter txpool.PendingFilter) map[common.Address][]*txpool.LazyTransaction {
	if !filter.OnlyRIP7560Txs {
		return nil
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()

	var pending []*txpool.LazyTransaction

	txs := pool.pending

	for i := 0; i < len(txs); i++ {
		pending = append(pending, &txpool.LazyTransaction{
			Pool:      pool,
			Hash:      txs[i].Hash(),
			Tx:        txs[i],
			Time:      txs[i].Time(),
			GasFeeCap: uint256.MustFromBig(txs[i].GasFeeCap()),
			GasTipCap: uint256.MustFromBig(txs[i].GasTipCap()),
			Gas:       txs[i].Gas(),
			BlobGas:   txs[i].BlobGas(),
		})
	}

	result := make(map[common.Address][]*txpool.LazyTransaction)
	result[common.Address{}] = pending
	// pool.pending = pool.pending[:0]
	return result
}

// SubscribeTransactions is not needed for the External Bundler AA sub pool and 'ch' will never be sent anything.
func (pool *RIP7560Pool) SubscribeTransactions(ch chan<- core.NewTxsEvent, _ bool) event.Subscription {
	return pool.txFeed.Subscribe(ch)
}

// RIP-7560 + RIP-7712 use 2D-nonce
func (pool *RIP7560Pool) Nonce(_ common.Address) uint64 {
	return 0
}

func (pool *RIP7560Pool) Stats() (int, int) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return len(pool.pending), 0
}

func (pool *RIP7560Pool) Content() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pending := make(map[common.Address][]*types.Transaction, len(pool.pending))
	pending[common.Address{}] = pool.pending
	return pending, nil
}

func (pool *RIP7560Pool) ContentFrom(_ common.Address) ([]*types.Transaction, []*types.Transaction) {
	return nil, nil
}

// Locals are not necessary for AA Pool
func (pool *RIP7560Pool) Locals() []common.Address {
	return []common.Address{}
}

// no TxStatusQueued status
func (pool *RIP7560Pool) Status(hash common.Hash) txpool.TxStatus {
	_, ok := pool.pendingMap[hash]
	if !ok {
		return txpool.TxStatusUnknown
	}
	return txpool.TxStatusPending
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

	var errs []error

	log.Warn("RIP7560Pool Add", "count", len(txs))

	for _, tx := range txs {
		pool.pendingMap[tx.Hash()] = tx
	}

	pool.pending = append(pool.pending, txs...)

	pool.txFeed.Send(core.NewTxsEvent{Txs: txs})

	return errs
}

func (pool *RIP7560Pool) Pop7560(txs []*types.Transaction) []error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	var errs []error

	log.Warn("RIP7560Pool Pop", "count", len(txs))
	var txsCopy []*types.Transaction
	for _, tx := range txs {
		delete(pool.pendingMap, tx.Hash())
	}

	for _, tx := range pool.pending {
		// if in pendingMap, put in pending
		if _, ok := pool.pendingMap[tx.Hash()]; ok {
			txsCopy = append(txsCopy, tx)
		}
	}

	pool.pending = pool.pending[:0]
	pool.pending = append(pool.pending, txsCopy...)

	return errs
}
