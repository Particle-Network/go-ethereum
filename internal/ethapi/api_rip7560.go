package ethapi

import (
	"context"
	"math"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/eth/gasestimator"
	"github.com/ethereum/go-ethereum/rpc"
)

type RIP7560UsedGas struct {
	ValidationGas hexutil.Uint64 `json:"validationGas"`
	ExecutionGas  hexutil.Uint64 `json:"executionGas"`
}

func DoEstimateRIP7560TransactionGas(ctx context.Context, b Backend, args TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *StateOverride, gasCap uint64) (*RIP7560UsedGas, error) {
	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	if err = overrides.Apply(state); err != nil {
		return nil, err
	}
	// Construct the gas estimator option from the user input
	chainConfig := b.ChainConfig()
	bc := NewChainContext(ctx, b)
	tx := args.ToTransaction()

	gp := new(core.GasPool).AddGas(math.MaxUint64)
	payment, prepaidGas, err := core.PrepayGas(chainConfig, gp, header, tx, state)
	if err != nil {
		return nil, err
	}
	opts := &gasestimator.Options{
		Config:     chainConfig,
		Chain:      bc,
		Header:     header,
		State:      state,
		ErrorRatio: estimateGasErrorRatio,
		Payment:    payment,
		PrepaidGas: prepaidGas,
	}

	vg, err := gasestimator.EstimateRIP7560Validation(ctx, tx, opts, gasCap)
	if err != nil {
		return nil, err
	}

	eg, _, err := gasestimator.EstimateRIP7560Execution(ctx, tx, opts, gasCap)
	if err != nil {
		return nil, err
	}

	return &RIP7560UsedGas{
		ValidationGas: hexutil.Uint64(vg),
		ExecutionGas:  hexutil.Uint64(eg),
	}, nil
}

func (s *BlockChainAPI) EstimateRIP7560TransactionGas(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash, overrides *StateOverride) (*RIP7560UsedGas, error) {
	bNrOrHash := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	if blockNrOrHash != nil {
		bNrOrHash = *blockNrOrHash
	}

	// TODO: Configure RIP-7560 enabled devnet option
	// header, err := headerByNumberOrHash(ctx, s.b, bNrOrHash)
	// if err != nil {
	// 	return 0, err
	// }

	// if s.b.ChainConfig().IsRIP7560(header.Number) {
	// 	return 0, fmt.Errorf("cannot estimate gas for RIP-7560 tx on pre-bedrock block %v", header.Number)
	// }

	return DoEstimateRIP7560TransactionGas(ctx, s.b, args, bNrOrHash, overrides, s.b.RPCGasCap())
}
