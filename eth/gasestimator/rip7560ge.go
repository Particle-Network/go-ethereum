// Copyright 2023 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package gasestimator

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

var RIP7560TxBaseGas uint64 = 15000

func callRIP7560Validation(
	ctx context.Context,
	opts *Options,
	tx *types.Transaction,
	gasLimit uint64) (*core.ValidationPhaseResult, *state.StateDB, error) {

	st := tx.Rip7560TransactionData()
	// Configure the call for this specific execution (and revert the change after)
	defer func(gas uint64) { st.ValidationGas = gas }(st.ValidationGas)
	st.ValidationGas = gasLimit

	// Execute the call and separate execution faults caused by a lack of gas or
	// other non-fixable conditions
	var (
		blockContext = core.NewEVMBlockContext(opts.Header, opts.Chain, nil)
		txContext    = vm.TxContext{
			Origin:   *tx.Rip7560TransactionData().Sender,
			GasPrice: tx.GasFeeCap(),
		}

		dirtyState = opts.State.Copy()
		evm        = vm.NewEVM(blockContext, txContext, dirtyState, opts.Config, vm.Config{NoBaseFee: true})
	)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Gas Pool is set to half of the maximum possible gas to prevent overflow
	vpr, err := core.ApplyRIP7560ValidationPhases(
		opts.Config,
		opts.Chain,
		evm.Config,
		new(core.GasPool).AddGas(math.MaxUint64/2),
		dirtyState,
		&opts.Header.Coinbase,
		opts.Header,
		tx,
		true)

	if err != nil {
		if errors.Is(err, vm.ErrOutOfGas) {
			return nil, nil, nil // Special case, raise gas limit
		}
		return nil, nil, err // Bail out
	}
	return vpr, dirtyState, nil
}

func EstimateRIP7560Validation(ctx context.Context, tx *types.Transaction, opts *Options, gasCap uint64) (*core.ValidationPhaseResult, error) {
	// First calculate the tx hash
	// signer := types.MakeSigner(opts.Config, opts.Header.Number, opts.Header.Time)
	// signingHash := signer.Hash(tx)
	// Binary search the gas limit, as it may need to be higher than the amount used
	st := tx.Rip7560TransactionData()
	gasLimit := st.ValidationGas
	var (
		lo uint64 // lowest-known gas limit where tx execution fails
		hi uint64 // lowest-known gas limit where tx execution succeeds
	)
	// Determine the highest gas limit can be used during the estimation.
	hi = opts.Header.GasLimit
	if gasLimit >= params.TxGas {
		hi = gasLimit
	}
	// Normalize the max fee per gas the call is willing to spend.
	// var feeCap *big.Int
	// if st.GasFeeCap != nil {
	// 	feeCap = st.GasFeeCap
	// } else {
	// 	feeCap = common.Big0
	// }
	// Recap the highest gas limit with account's available balance.
	// if feeCap.BitLen() != 0 {
	// 	var payment common.Address
	// 	if len(st.PaymasterData) < 20 {
	// 		payment = *st.Sender
	// 	} else {
	// 		payment = common.BytesToAddress(st.PaymasterData[:20])
	// 	}
	// 	balance := opts.State.GetBalance(payment).ToBig()

	// 	allowance := new(big.Int).Div(balance, feeCap)

	// 	// If the allowance is larger than maximum uint64, skip checking
	// 	if allowance.IsUint64() && hi > allowance.Uint64() {
	// 		log.Debug("Gas estimation capped by limited funds", "original", hi, "balance", balance,
	// 			"maxFeePerGas", feeCap, "fundable", allowance)
	// 		hi = allowance.Uint64()
	// 	}
	// }
	// // Recap the highest gas allowance with specified gascap.
	// if gasCap != 0 && hi > gasCap {
	// 	log.Debug("Caller gas above allowance, capping", "requested", hi, "cap", gasCap)
	// 	hi = gasCap
	// }

	// We first execute the transaction at the highest allowable gas limit, since if this fails we
	// can return error immediately.
	vpr, statedb, err := callRIP7560Validation(ctx, opts, tx, hi)
	if err != nil {
		return nil, err
	} else if vpr == nil && err == nil {
		return nil, fmt.Errorf("gas required exceeds allowance (%d)", hi)
	}
	// For almost any transaction, the gas consumed by the unconstrained execution
	// above lower-bounds the gas limit required for it to succeed. One exception
	// is those that explicitly check gas remaining in order to execute within a
	// given limit, but we probably don't want to return the lowest possible gas
	// limit for these cases anyway.
	vpUsedGas := vpr.NonceValidationUsedGas + vpr.ValidationUsedGas + vpr.DeploymentUsedGas + vpr.PmValidationUsedGas
	lo = vpUsedGas - 1

	// There's a fairly high chance for the transaction to execute successfully
	// with gasLimit set to the first execution's usedGas + gasRefund. Explicitly
	// check that gas amount and use as a limit for the binary search.
	// optimisticGasLimit := (vpUsedGas + params.CallStipend) * 64 / 63
	// if optimisticGasLimit < hi {
	// 	vpr, statedb, err = executeRIP7560Validation(ctx, opts, tx, optimisticGasLimit, signingHash)
	// 	if err != nil {
	// 		// This should not happen under normal conditions since if we make it this far the
	// 		// transaction had run without error at least once before.
	// 		log.Error("Execution error in estimate gas", "err", err)
	// 		return 0, err
	// 	}
	// 	if vpr == nil {
	// 		lo = optimisticGasLimit
	// 	} else {
	// 		hi = optimisticGasLimit
	// 	}
	// }
	// Binary search for the smallest gas limit that allows the tx to execute successfully.
	for lo+1 < hi {
		if opts.ErrorRatio > 0 {
			// It is a bit pointless to return a perfect estimation, as changing
			// network conditions require the caller to bump it up anyway. Since
			// wallets tend to use 20-25% bump, allowing a small approximation
			// error is fine (as long as it's upwards).
			if float64(hi-lo)/float64(hi) < opts.ErrorRatio {
				break
			}
		}
		mid := (hi + lo) / 2
		if mid > lo*2 {
			// Most txs don't need much higher gas limit than their gas used, and most txs don't
			// require near the full block limit of gas, so the selection of where to bisect the
			// range here is skewed to favor the low side.
			mid = lo * 2
		}
		vpr, statedb, err = callRIP7560Validation(ctx, opts, tx, mid)
		if err != nil {
			// This should not happen under normal conditions since if we make it this far the
			// transaction had run without error at least once before.
			log.Error("Execution error in estimate gas", "err", err)
			return nil, err
		}
		if vpr == nil {
			lo = mid
		} else {
			hi = mid
		}
	}

	opts.ValidationPhaseResult = vpr
	opts.State = statedb
	return vpr, nil
}

func callRIP7560Execution(
	ctx context.Context,
	opts *Options,
	tx *types.Transaction,
	gasLimit uint64) (bool, *core.ExecutionResult, *core.ExecutionResult, error) {
	st := tx.Rip7560TransactionData()
	// Configure the call for this specific execution (and revert the change after)
	defer func(gas uint64) { st.Gas = gas }(st.Gas)
	st.CallGas = gasLimit

	// Execute the call and separate execution faults caused by a lack of gas or
	// other non-fixable conditions
	var (
		blockContext = core.NewEVMBlockContext(opts.Header, opts.Chain, nil)
		txContext    = vm.TxContext{
			Origin:   *tx.Rip7560TransactionData().Sender,
			GasPrice: tx.GasFeeCap(),
		}

		dirtyState = opts.State.Copy()
		evm        = vm.NewEVM(blockContext, txContext, dirtyState, opts.Config, vm.Config{NoBaseFee: true})
	)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Gas Pool is set to half of the maximum possible gas to prevent overflow.
	// Unused gas penalty is not taken into account, since it does not affect the estimation.
	exr, ppr, _, err := core.ApplyRIP7560ExecutionPhase(
		opts.Config,
		opts.Chain,
		vm.Config{NoBaseFee: true},
		new(core.GasPool).AddGas(math.MaxUint64/2),
		dirtyState,
		&opts.Header.Coinbase,
		opts.Header,
		opts.ValidationPhaseResult,
		opts.Payment,
		opts.PrepaidGas)

	if err != nil {
		if errors.Is(err, core.ErrIntrinsicGas) {
			return true, nil, nil, nil // Special case, raise gas limit
		}
		return true, nil, nil, err // Bail out
	}
	return false, exr, ppr, nil
}

func EstimateRIP7560Execution(ctx context.Context, tx *types.Transaction, opts *Options, gasCap uint64) (uint64, uint64, uint64, []byte, error) {
	// Binary search the gas limit, as it may need to be higher than the amount used
	st := tx.Rip7560TransactionData()
	gasLimit := st.CallGas
	var (
		lo uint64 // lowest-known gas limit where tx execution fails
		hi uint64 // lowest-known gas limit where tx execution succeeds
	)
	// Determine the highest gas limit can be used during the estimation.
	hi = opts.Header.GasLimit
	if gasLimit >= params.TxGas {
		hi = gasLimit
	}
	// Normalize the max fee per gas the call is willing to spend.
	var feeCap *big.Int
	if st.GasFeeCap != nil {
		feeCap = st.GasFeeCap
	} else {
		feeCap = common.Big0
	}
	// Recap the highest gas limit with account's available balance.
	if feeCap.BitLen() != 0 {
		var payment common.Address
		if len(st.PaymasterData) < 20 {
			payment = *st.Sender
		} else {
			payment = common.BytesToAddress(st.PaymasterData[:20])
		}
		balance := opts.State.GetBalance(payment).ToBig()

		allowance := new(big.Int).Div(balance, feeCap)

		// If the allowance is larger than maximum uint64, skip checking
		if allowance.IsUint64() && hi > allowance.Uint64() {
			log.Debug("Gas estimation capped by limited funds", "original", hi, "balance", balance,
				"maxFeePerGas", feeCap, "fundable", allowance)
			hi = allowance.Uint64()
		}
	}
	// Recap the highest gas allowance with specified gascap.
	if gasCap != 0 && hi > gasCap {
		log.Debug("Caller gas above allowance, capping", "requested", hi, "cap", gasCap)
		hi = gasCap
	}

	// We first execute the transaction at the highest allowable gas limit, since if this fails we
	// can return error immediately.
	failed, exr, ppr, err := callRIP7560Execution(ctx, opts, tx, hi)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	if failed {
		if exr != nil && ppr != nil {
			if !errors.Is(exr.Err, vm.ErrOutOfGas) {
				return 0, 0, 0, exr.Revert(), exr.Err
			} else if !errors.Is(ppr.Err, vm.ErrOutOfGas) {
				return 0, 0, 0, ppr.Revert(), ppr.Err
			}
		}
		return 0, 0, 0, nil, fmt.Errorf("gas required exceeds allowance (%d)", hi)
	}
	// For almost any transaction, the gas consumed by the unconstrained execution
	// above lower-bounds the gas limit required for it to succeed. One exception
	// is those that explicitly check gas remaining in order to execute within a
	// given limit, but we probably don't want to return the lowest possible gas
	// limit for these cases anyway.
	callGas := exr.UsedGas
	postOpGas := uint64(0)
	if ppr == nil {
		lo = exr.UsedGas - 1
	} else {
		lo = exr.UsedGas + ppr.UsedGas - 1
		postOpGas = ppr.UsedGas
	}

	// There's a fairly high chance for the transaction to execute successfully
	// with gasLimit set to the first execution's usedGas + gasRefund. Explicitly
	// check that gas amount and use as a limit for the binary search.
	// var optimisticGasLimit uint64
	// if ppr == nil {
	// 	optimisticGasLimit = (exr.UsedGas + exr.RefundedGas + params.CallStipend) * 64 / 63
	// } else {
	// 	optimisticGasLimit = (exr.UsedGas + exr.RefundedGas + ppr.UsedGas + ppr.RefundedGas + params.CallStipend) * 64 / 63
	// }
	// if optimisticGasLimit < hi {
	// 	failed, _, _, err = callRIP7560Execution(ctx, opts, tx, optimisticGasLimit)
	// 	if err != nil {
	// 		// This should not happen under normal conditions since if we make it this far the
	// 		// transaction had run without error at least once before.
	// 		log.Error("Execution error in estimate gas", "err", err)
	// 		return 0, 0, nil, err
	// 	}
	// 	if failed {
	// 		lo = optimisticGasLimit
	// 	} else {
	// 		hi = optimisticGasLimit
	// 	}
	// }

	// Binary search for the smallest gas limit that allows the tx to execute successfully.
	for lo+1 < hi {
		if opts.ErrorRatio > 0 {
			// It is a bit pointless to return a perfect estimation, as changing
			// network conditions require the caller to bump it up anyway. Since
			// wallets tend to use 20-25% bump, allowing a small approximation
			// error is fine (as long as it's upwards).
			if float64(hi-lo)/float64(hi) < opts.ErrorRatio {
				break
			}
		}
		mid := (hi + lo) / 2
		if mid > lo*2 {
			// Most txs don't need much higher gas limit than their gas used, and most txs don't
			// require near the full block limit of gas, so the selection of where to bisect the
			// range here is skewed to favor the low side.
			mid = lo * 2
		}
		failed, _exer, _ppr, err := callRIP7560Execution(ctx, opts, tx, mid)
		if err != nil {
			// This should not happen under normal conditions since if we make it this far the
			// transaction had run without error at least once before.
			log.Error("Execution error in estimate gas", "err", err)
			return 0, 0, 0, nil, err
		}
		if failed {
			lo = mid
		} else {
			hi = mid
			callGas = _exer.UsedGas
			postOpGas = _ppr.UsedGas
		}
	}
	return hi, callGas, postOpGas, nil, nil
}
