package ethapi

import (
	"context"
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/gasestimator"
	"github.com/ethereum/go-ethereum/rpc"
)

type RIP7560TxSignatureHash struct {
	Hash common.Hash `json:"hash"`
}

type RIP7560UsedGas struct {
	BaseGas                hexutil.Uint64 `json:"BaseGas"`
	NonceValidationGas     hexutil.Uint64 `json:"nonceValidationGas"`
	DeploymentGas          hexutil.Uint64 `json:"deploymentGas"`
	AccountValidationGas   hexutil.Uint64 `json:"accountValidationGas"`
	PaymasterValidationGas hexutil.Uint64 `json:"paymasterValidationGas"`
	// ValidationGas hexutil.Uint64 `json:"validationGas"`
	// ExecutionGas  hexutil.Uint64 `json:"executionGas"`
	CallGas   hexutil.Uint64 `json:"callGas"`
	PostOpGas hexutil.Uint64 `json:"postOpGas"`
}

func DoEstimateRIP7560TransactionGas(
	ctx context.Context,
	b Backend,
	args TransactionArgs,
	blockNrOrHash rpc.BlockNumberOrHash,
	overrides *StateOverride,
	gasCap uint64) (*RIP7560UsedGas, error) {
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

	vpr, err := gasestimator.EstimateRIP7560Validation(ctx, tx, opts, gasCap)
	if err != nil {
		return nil, err
	}

	_, callGas, postOpGas, _, err := gasestimator.EstimateRIP7560Execution(ctx, tx, opts, gasCap)
	if err != nil {
		return nil, err
	}

	return &RIP7560UsedGas{
		BaseGas:                15000,
		NonceValidationGas:     hexutil.Uint64(vpr.NonceValidationUsedGas + 1000),
		DeploymentGas:          hexutil.Uint64(vpr.DeploymentUsedGas + 1000),
		AccountValidationGas:   hexutil.Uint64(vpr.ValidationUsedGas + 1000),
		PaymasterValidationGas: hexutil.Uint64(vpr.PmValidationUsedGas + 1000),
		CallGas:                hexutil.Uint64(callGas + 1000),
		PostOpGas:              hexutil.Uint64(postOpGas + 1000),
	}, nil
}

func (s *BlockChainAPI) EstimateRIP7560TransactionGas(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash, overrides *StateOverride) (*RIP7560UsedGas, error) {
	bNrOrHash := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	if blockNrOrHash != nil {
		bNrOrHash = *blockNrOrHash
	}

	return DoEstimateRIP7560TransactionGas(ctx, s.b, args, bNrOrHash, overrides, s.b.RPCGasCap())
}

func (s *BlockChainAPI) SignatureHash(ctx context.Context, args TransactionArgs) (*RIP7560TxSignatureHash, error) {
	tx := args.ToTransaction()
	chainConfig := s.b.ChainConfig()
	signer := types.NewRIP7560Signer(chainConfig.ChainID)
	signingHash := signer.Hash(tx)

	return &RIP7560TxSignatureHash{
		Hash: signingHash,
	}, nil
}
