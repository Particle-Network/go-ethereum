package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	cmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

var RIP7560TxBaseGas uint64 = 15000
var EntryPointAddress = common.HexToAddress("0x0000000000000000000000000000000000007560")
var DeployerCallerAddress = common.HexToAddress("0x00000000000000000000000000000000ffff7560")
var NonceManagerAddress = common.HexToAddress("0x0000000000000000000000000000000000007712") // some as 0x4200000000000000000000000000000000000024

const MaxContextSize = 65536

type ValidationPhaseResult struct {
	TxIndex                int
	Tx                     *types.Transaction
	TxHash                 common.Hash
	PaymasterContext       []byte
	NonceValidationUsedGas uint64
	DeploymentUsedGas      uint64
	ValidationUsedGas      uint64
	PmValidationUsedGas    uint64
	SenderValidAfter       uint64
	SenderValidUntil       uint64
	PmValidAfter           uint64
	PmValidUntil           uint64
	Payment                *common.Address
	PrepaidGas             *uint256.Int
}

func HandleRIP7560Transactions(
	chainConfig *params.ChainConfig,
	chainCtx ChainContext,
	vmConfig vm.Config,
	gp *GasPool,
	statedb *state.StateDB,
	coinbase *common.Address,
	header *types.Header,
	transactions []*types.Transaction,
	index int,
) ([]*types.Transaction, types.Receipts, []*types.Log, error) {
	txs := make([]*types.Transaction, 0)
	receipts := make([]*types.Receipt, 0)
	logs := make([]*types.Log, 0)

	for i, tx := range transactions {
		statedb.SetTxContext(tx.Hash(), index+i)

		_, receipt, _logs, err := ApplyRIP7560Transaction(chainConfig, chainCtx, vmConfig, gp, statedb, coinbase, header, tx, i)
		if err != nil {
			log.Error("Failed to handleRip7560Transactions", "err", err)
			continue
		}
		txs = append(txs, tx)
		receipts = append(receipts, receipt)
		logs = append(logs, _logs...)
	}

	return txs, receipts, logs, nil
}

/*
When processing a transaction of type AA_TX_TYPE, however, multiple execution frames will be created.
The full list of possible frames tries to replicate the ERC-4337 flow:

=> Validation Phase
* 2D-nonce validation for RIP7712
* sender deployment frame (once per account)
* sender validation frame (required)
* paymaster validation frame (optional)
=> Execution Phase
* sender execution frame (required)
* paymaster post-transaction frame (optional)
*/
func ApplyRIP7560Transaction(
	chainConfig *params.ChainConfig,
	chain ChainContext,
	vmConfig vm.Config,
	gp *GasPool,
	statedb *state.StateDB,
	coinbase *common.Address,
	header *types.Header,
	transaction *types.Transaction,
	txindex int,
) (*types.Transaction, *types.Receipt, []*types.Log, error) {

	if transaction.Type() != types.RIP7560TxType {
		return nil, nil, nil, fmt.Errorf("not RIP7560 transaction")
	}

	// No issues should occur during the validation phase.
	// However, in the unlikely event that something goes wrong,
	// we will revert to the previous state and invalidate the transaction.
	var (
		snapshot = statedb.Snapshot()
		prevGas  = gp.Gas()
	)

	statedb.SetTxContext(transaction.Hash(), txindex)
	log.Info("[RIP-7560] Validation Phase - BuyGas")
	payment, prepaidGas, err := PrepayGas(chainConfig, gp, header, transaction, statedb)
	if err != nil {
		log.Warn("[RIP-7560] Failed to prepayGas", "err", err)
		return nil, nil, nil, err
	}

	var vpr *ValidationPhaseResult
	log.Info("[RIP-7560] Validation Phase - Validation")

	vpr, err = ApplyRIP7560ValidationPhases(chainConfig, chain, vmConfig, gp, statedb, coinbase, header, transaction, false)
	if err != nil {
		log.Warn("[RIP-7560] Failed to ApplyRIP7560ValidationPhases", "err", err)
		// If an error occurs in the validation phase, invalidate the transaction
		statedb.RevertToSnapshot(snapshot)
		gp.SetGas(prevGas)
		return nil, nil, nil, err
	}

	statedb.IntermediateRoot(true)

	vpr.Payment = payment
	vpr.PrepaidGas = prepaidGas

	// *** This is the line separating the Validation and Execution phases *** //
	// It should be separated to implement the mempool-friendly AA RIP (number not assigned yet)

	// TIP: this will miss all validation phase events - pass in 'vpr'
	statedb.SetTxContext(vpr.Tx.Hash(), txindex+2000)
	executionResult, paymasterPostOpResult, cumulativeGasUsed, err := ApplyRIP7560ExecutionPhase(
		chainConfig, chain, vmConfig, gp, statedb, coinbase, header, vpr, vpr.Payment, vpr.PrepaidGas)

	root := statedb.IntermediateRoot(true).Bytes()
	receipt := &types.Receipt{Type: vpr.Tx.Type(), PostState: root, CumulativeGasUsed: cumulativeGasUsed}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(vpr.Tx.Hash(), header.Number.Uint64(), header.Hash())

	if executionResult.Failed() || (paymasterPostOpResult != nil && paymasterPostOpResult.Failed()) {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}

	// receipt.TxHash = vpr.Tx.Hash()
	// receipt.GasUsed = executionResult.UsedGas

	// receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	// receipt.BlockHash = header.Hash()
	// receipt.BlockNumber = header.Number
	// receipt.TransactionIndex = uint(statedb.TxIndex())

	if err != nil {
		return nil, nil, nil, err
	}

	return transaction, receipt, receipt.Logs, nil
}

// Prepay gas from sender or paymaster
func PrepayGas(
	chainConfig *params.ChainConfig,
	gp *GasPool,
	header *types.Header,
	tx *types.Transaction,
	state vm.StateDB) (*common.Address, *uint256.Int, error) {

	txData := tx.Rip7560TransactionData()
	gasLimit := txData.Gas + txData.ValidationGas + txData.PaymasterGas + txData.PostOpGas + RIP7560TxBaseGas
	// Store prepaid values in gas units
	gasNeed := new(uint256.Int).SetUint64(gasLimit)
	// adjust effectiveGasPrice
	effectiveGasPrice := cmath.BigMin(new(big.Int).Add(txData.GasTipCap, header.BaseFee), txData.GasFeeCap)
	gasNeedValue := new(uint256.Int).Mul(gasNeed, new(uint256.Int).SetUint64(effectiveGasPrice.Uint64()))

	balanceCheck := new(uint256.Int).Set(gasNeedValue)

	chargeFrom := *txData.Sender
	// txData.PaymasterData[:20] is PaymasterAddress
	if len(txData.PaymasterData) >= 20 {
		chargeFrom = [20]byte(txData.PaymasterData[:20])
	}

	if have, want := state.GetBalance(chargeFrom), balanceCheck; have.Cmp(want) < 0 {
		return &common.Address{}, new(uint256.Int), fmt.Errorf("%w: address %v have %v want %v", ErrInsufficientFunds, chargeFrom.Hex(), have, want)
	}

	state.SubBalance(chargeFrom, gasNeedValue, 0x01) // tracing.BalanceChangeReason TODO: replace 0x01 to real reason
	err := gp.SubGas(gasNeed.Uint64())
	if err != nil {
		return &common.Address{}, new(uint256.Int), err
	}
	return &chargeFrom, gasNeed, nil
}

func ApplyRIP7560ValidationPhases(
	chainConfig *params.ChainConfig,
	chainCtx ChainContext,
	vmConfig vm.Config,
	gp *GasPool,
	statedb *state.StateDB,
	coinbase *common.Address,
	header *types.Header,
	tx *types.Transaction,
	isEstimate bool) (*ValidationPhaseResult, error) {
	blockContext := NewEVMBlockContext(header, chainCtx, coinbase)

	txData := tx.Rip7560TransactionData()
	txContext := vm.TxContext{
		Origin:   *txData.Sender,
		GasPrice: tx.GasFeeCap(),
	}
	evm := vm.NewEVM(blockContext, txContext, statedb, chainConfig, vmConfig)

	/*** Nonce Validation Frame ***/
	// Nonce Validation Frame no state change, when failed and use legacy-nonce, nonce += 1.
	nonceValidationMsg := prepareNonceValidationMessage(tx)
	var nonceValidationUsedGas uint64
	if nonceValidationMsg != nil {
		log.Info("[RIP-7560] Nonce Validation Frame", "nonceType", "2D-nonce")
		result, err := ApplyMessage(evm, nonceValidationMsg, gp)
		if err != nil {
			log.Error("[RIP-7560] Nonce Validation Frame", "ApplyMessage.Err", err)
			return nil, err
		}
		if result.Err != nil {
			log.Error("[RIP-7560] Nonce Validation Frame", "result.Err", result.Err)
			return nil, result.Err
		}
		nonceValidationUsedGas = result.UsedGas
	} else {
		log.Info("[RIP-7560] Nonce Validation Frame", "nonceType", "legacy-nonce")
		// Use legacy nonce validation
		senderNonce := statedb.GetNonce(*txData.Sender)
		// TODO: add error messages like ErrNonceTooLow, ErrNonceTooHigh, etc.
		if msgNonce := txData.BigNonce.Uint64(); senderNonce != msgNonce {
			log.Error("RIP-7560] nonce validation failed 01- invalid transaction", "msgNonce", msgNonce, "senderNonce", senderNonce)
			return nil, errors.New("[RIP-7560] nonce validation failed 01- invalid transaction")
		} else if senderNonce == 0 {
			deployerData := txData.DeployerData
			if len(deployerData) < 20 {
				return nil, errors.New("[RIP-7560] nonce validation failed 02- invalid transaction")
			}
			if bytes.Equal(deployerData[:20], common.Address{}.Bytes()) {
				return nil, errors.New("[RIP-7560] nonce validation failed 03- invalid transaction")
			}
		} else {
			// tx success or failed, whatever, nonce + 1
			statedb.SetNonce(txContext.Origin, senderNonce+1)
		}
	}

	/*** Deployer Frame ***/
	deployerMsg := prepareDeployerMessage(tx, nonceValidationUsedGas)
	var deploymentUsedGas uint64
	if deployerMsg != nil {
		result, err := ApplyMessage(evm, deployerMsg, gp)
		if err != nil {
			log.Error("[RIP-7560] Deployer Frame", "ApplyMessage.Err", err)
			return nil, err
		}
		deployedAddr := common.BytesToAddress(result.ReturnData)
		log.Info("[RIP-7560]", "deployedAddr", deployedAddr.Hex())
		if result.Failed() || statedb.GetCode(deployedAddr) == nil {
			return nil, errors.New("[RIP-7560] account deployment failed - invalid transaction")
		} else if deployedAddr != *txData.Sender {
			return nil, errors.New("[RIP-7560] deployed address mismatch - invalid transaction")
		}
		// TODO : would be handled inside IntrinsicGas
		deploymentUsedGas = result.UsedGas + params.TxGasContractCreation
	}

	signer := types.NewRIP7560Signer(chainConfig.ChainID)
	signingHash := common.Hash{}
	if !isEstimate {
		signingHash = signer.Hash(tx)
	}
	// signingHash := common.Hash{}

	/*** Account Validation Frame ***/
	// log.Warn("[RIP-7560] Account Validation Frame",  "txhash", tx.Hash())
	acValidationUsedGas, acValidAfter, acValidUntil, err := applyAccountValidationFrame(
		chainConfig, evm, gp, statedb, header, tx, signingHash, nonceValidationUsedGas, deploymentUsedGas, isEstimate)

	if err != nil {
		log.Error("[RIP-7560] Account Validation Frame", "err", err)
		return nil, err
	}

	/*** Paymaster Validation Frame ***/
	paymasterContext, pmValidationUsedGas, pmValidAfter, pmValidUntil, err := applyPaymasterValidationFrame(
		chainConfig, evm, gp, statedb, header, tx, signingHash, isEstimate)
	if err != nil {
		log.Error("[RIP-7560] Paymaster Validation Frame", "err", err)
		return nil, err
	}
	vpr := &ValidationPhaseResult{
		Tx:                     tx,
		TxHash:                 tx.Hash(),
		PaymasterContext:       paymasterContext,
		NonceValidationUsedGas: nonceValidationUsedGas,
		DeploymentUsedGas:      deploymentUsedGas,
		ValidationUsedGas:      acValidationUsedGas + RIP7560TxBaseGas,
		PmValidationUsedGas:    pmValidationUsedGas,
		SenderValidAfter:       acValidAfter,
		SenderValidUntil:       acValidUntil,
		PmValidAfter:           pmValidAfter,
		PmValidUntil:           pmValidUntil,
	}
	log.Info("[RIP-7560] ValidationPhaseResult", "vpr", vpr)

	return vpr, nil
}

func applyAccountValidationFrame(
	_ *params.ChainConfig,
	evm *vm.EVM,
	gp *GasPool,
	_ *state.StateDB,
	header *types.Header,
	tx *types.Transaction,
	signingHash common.Hash,
	nonceValidationUsedGas uint64,
	deploymentUsedGas uint64,
	isEstimate bool) (uint64, uint64, uint64, error) {

	accountValidationMsg, err := prepareAccountValidationMessage(tx, signingHash, nonceValidationUsedGas, deploymentUsedGas)
	if err != nil {
		log.Error("[RIP-7560] prepareAccountValidation", "Err", err)
		return 0, 0, 0, err
	}

	result, err := ApplyMessage(evm, accountValidationMsg, gp)
	if err != nil {
		log.Error("[RIP-7560] Account Validation Frame", "ApplyMessage.Err", err)
		return 0, 0, 0, err
	}
	if result.Err != nil {
		log.Error("[RIP-7560] Account Validation Frame", "result.Err", result.Err)
		if !isEstimate {
			return 0, 0, 0, result.Err
		}
	}
	validAfter, validUntil, err := validateAccountReturnData(result.ReturnData)
	if err != nil {
		log.Error("[RIP-7560] Account Validation Frame", "validateAccountReturnData.Err", err)
		if !isEstimate {
			return 0, 0, 0, err
		}
	}
	err = validateValidityTimeRange(header.Time, validAfter, validUntil)
	if err != nil {
		log.Error("[RIP-7560] Account Validation Frame", "validateValidityTimeRange.Err", err)
		if !isEstimate {
			return 0, 0, 0, err
		}
	}
	return result.UsedGas, validAfter, validUntil, nil
}

func applyPaymasterValidationFrame(
	_ *params.ChainConfig,
	evm *vm.EVM,
	gp *GasPool,
	statedb *state.StateDB,
	header *types.Header,
	tx *types.Transaction,
	signingHash common.Hash,
	isEstimate bool) ([]byte, uint64, uint64, uint64, error) {

	var pmValidationUsedGas uint64
	var pmContext []byte
	var pmValidAfter uint64
	var pmValidUntil uint64
	paymasterMsg, err := preparePaymasterValidationMessage(tx, signingHash)
	if err != nil {
		log.Error("[RIP-7560] Paymaster Validation Frame", "preparePaymasterValidationMessage.err", err)
		return nil, 0, 0, 0, err

	}
	if paymasterMsg != nil {
		resultPm, err := ApplyMessage(evm, paymasterMsg, gp)
		if err != nil {
			log.Error("[RIP-7560] Paymaster Validation Frame", "ApplyMessage.err", err)
			return nil, 0, 0, 0, err
		}
		statedb.IntermediateRoot(true)
		if resultPm.Failed() {
			return nil, 0, 0, 0, errors.New("paymaster validation failed - invalid transaction")
		}
		pmValidationUsedGas = resultPm.UsedGas
		pmContext, pmValidAfter, pmValidUntil, err = validatePaymasterReturnData(resultPm.ReturnData)
		if err != nil {
			log.Error("[RIP-7560] Paymaster Validation Frame", "validatePaymasterReturnData.err", err)
			// return nil, 0, 0, 0, err
			if !isEstimate {
				return nil, 0, 0, 0, err
			}
		}
		err = validateValidityTimeRange(header.Time, pmValidAfter, pmValidUntil)
		if err != nil {
			log.Error("[RIP-7560] Paymaster Validation Frame", "validateValidityTimeRange.err", err)
			if !isEstimate {
				return nil, 0, 0, 0, err
			}
		}
	}
	return pmContext, pmValidationUsedGas, pmValidAfter, pmValidUntil, nil
}

func ApplyRIP7560ExecutionPhase(
	config *params.ChainConfig,
	chainCtx ChainContext,
	vmConfig vm.Config,
	gp *GasPool,
	statedb *state.StateDB,
	coinbase *common.Address,
	header *types.Header,
	vpr *ValidationPhaseResult,
	payment *common.Address,
	prepaidGas *uint256.Int) (*ExecutionResult, *ExecutionResult, uint64, error) {

	// revert back here if postOp fails
	var snapshot = statedb.Snapshot()
	blockContext := NewEVMBlockContext(header, chainCtx, coinbase)
	message, _ := TransactionToMessage(vpr.Tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	txContext := NewEVMTxContext(message)
	txContext.Origin = *vpr.Tx.Rip7560TransactionData().Sender
	evm := vm.NewEVM(blockContext, txContext, statedb, config, vmConfig)

	executionMsg := prepareAccountExecutionMessage(evm.ChainConfig(), vpr.Tx)
	executionResult, err := ApplyMessage(evm, executionMsg, gp)
	if err != nil {
		log.Error("[RIP-7560] Execution Frame", "ApplyMessage.Err", err)
		return nil, nil, 0, err
	}
	log.Info("[RIP-7560] Execution gas info", "executionResult.UsedGas", executionResult.UsedGas)

	var paymasterPostOpResult *ExecutionResult
	if len(vpr.PaymasterContext) != 0 {
		paymasterPostOpResult, err = applyPaymasterPostOpFrame(vpr, executionResult, evm, gp)
		if err != nil {
			log.Error("[RIP-7560] Post-OP-transaction Frame", "applyPaymasterPostOpFrame.err", err)
			return nil, nil, 0, err
		}
		// revert the execution phase changes
		if paymasterPostOpResult.Failed() {
			log.Warn("[RIP-7560] Post-OP-transaction Frame - reverted", "paymasterPostOpResult", paymasterPostOpResult)
			statedb.RevertToSnapshot(snapshot)
		}
	}

	cumulativeGasUsed := vpr.NonceValidationUsedGas +
		vpr.ValidationUsedGas +
		vpr.DeploymentUsedGas +
		vpr.PmValidationUsedGas

	cumulativeGasUsed += executionResult.UsedGas
	if paymasterPostOpResult != nil {
		cumulativeGasUsed += paymasterPostOpResult.UsedGas
	}

	// calculation for intrinsicGas
	// TODO: integrated with code in state_transition
	// rules := evm.ChainConfig().Rules(evm.Context.BlockNumber, evm.Context.Random != nil, evm.Context.Time)
	// intrGas, err := IntrinsicGasWithOption(vpr.Tx.Data(), vpr.Tx.AccessList(), false, rules.IsHomestead, rules.IsIstanbul, rules.IsShanghai, true, false)
	// if err != nil {
	// 	return nil, nil, 0, err
	// }
	// cumulativeGasUsed += intrGas

	// apply a penalty && refund gas
	// TODO: If this value is not persistent, it should be modified to be managed on-chain config
	// const UNUSED_GAS_PENALTY_PERCENT = 10
	// gasPenalty := (prepaidGas.Uint64() - cumulativeGasUsed) * UNUSED_GAS_PENALTY_PERCENT / 100
	var gasPenalty uint64 = 0
	cumulativeGasUsed += gasPenalty
	refundGas := uint256.NewInt((prepaidGas.Uint64() - cumulativeGasUsed) * evm.Context.BaseFee.Uint64())
	statedb.AddBalance(*payment, refundGas, 0x01)
	gp.AddGas(prepaidGas.Uint64() - cumulativeGasUsed)

	if paymasterPostOpResult != nil {
		log.Info("[RIP-7560] Execution gas info", "paymasterPostOpResult.UsedGas", paymasterPostOpResult.UsedGas)
	}
	log.Info("[RIP-7560] Execution gas info", "cumulativeGasUsed", cumulativeGasUsed)

	return executionResult, paymasterPostOpResult, cumulativeGasUsed, nil
}

func applyPaymasterPostOpFrame(
	vpr *ValidationPhaseResult,
	executionResult *ExecutionResult,
	evm *vm.EVM,
	gp *GasPool) (*ExecutionResult, error) {
	var paymasterPostOpResult *ExecutionResult
	paymasterPostOpMsg, err := preparePostOpMessage(evm.ChainConfig(), vpr, executionResult)
	if err != nil {
		return nil, err
	}
	paymasterPostOpResult, err = ApplyMessage(evm, paymasterPostOpMsg, gp)
	if err != nil {
		return nil, err
	}
	// TODO: revert the execution phase changes
	return paymasterPostOpResult, nil
}

func prepareNonceValidationMessage(baseTx *types.Transaction) *Message {
	tx := baseTx.Rip7560TransactionData()

	// TODO: add error when bigNonce value over 32 bytes
	key := make([]byte, 32)
	fromBig, _ := uint256.FromBig(tx.BigNonce)
	fromBig.WriteToSlice(key)

	// Use legacy nonce validation if the key is all zeros
	if bytes.Equal(key[:24], make([]byte, 24)) {
		return nil
	}

	// call NonceManager fallback
	nonceValidationData := make([]byte, 0)
	nonceValidationData = append(nonceValidationData[:], tx.Sender.Bytes()...)
	nonceValidationData = append(nonceValidationData[:], key...)

	return &Message{
		From:              EntryPointAddress,
		To:                &NonceManagerAddress,
		Value:             big.NewInt(0),
		GasLimit:          tx.ValidationGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              nonceValidationData,
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		// IsRip7560Frame:    true,
	}
}

func prepareDeployerMessage(baseTx *types.Transaction, nonceValidationUsedGas uint64) *Message {
	tx := baseTx.Rip7560TransactionData()
	if len(tx.DeployerData) < 20 {
		return nil
	}
	var deployerAddress common.Address = [20]byte(tx.DeployerData[0:20])
	return &Message{
		From:              DeployerCallerAddress,
		To:                &deployerAddress,
		Value:             big.NewInt(0),
		GasLimit:          tx.ValidationGas - nonceValidationUsedGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              tx.DeployerData[20:],
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		// IsRip7560Frame:    true,
	}
}

func prepareAccountValidationMessage(
	baseTx *types.Transaction,
	signingHash common.Hash,
	nonceValidationUsedGas,
	deploymentUsedGas uint64) (*Message, error) {
	tx := baseTx.Rip7560TransactionData()
	jsondata := `[
	{"type":"function","name":"validateTransaction","inputs": [{"name": "version","type": "uint256"},{"name": "txHash","type": "bytes32"},{"name": "transaction","type": "bytes"}]}
	]`

	validateTransactionAbi, err := abi.JSON(strings.NewReader(jsondata))
	if err != nil {
		return nil, err
	}
	txAbiEncoding, _ := tx.AbiEncode()
	validateTransactionData, err := validateTransactionAbi.Pack("validateTransaction", big.NewInt(1), signingHash, txAbiEncoding)
	if err != nil {
		return nil, err
	}
	log.Warn("[RIP-7560] prepareAccountValidationMessage", "signingHash", signingHash, "validateTransactionData", common.Bytes2Hex(validateTransactionData))

	return &Message{
		From:              EntryPointAddress,
		To:                tx.Sender,
		Value:             big.NewInt(0),
		GasLimit:          tx.ValidationGas - nonceValidationUsedGas - deploymentUsedGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              validateTransactionData,
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		// IsRip7560Frame:    true,
	}, nil
}

func preparePaymasterValidationMessage(baseTx *types.Transaction, signingHash common.Hash) (*Message, error) {
	tx := baseTx.Rip7560TransactionData()
	if len(tx.PaymasterData) < 20 {
		return nil, nil
	}
	var paymasterAddress common.Address = [20]byte(tx.PaymasterData[0:20])
	jsondata := `[
		{"type":"function","name":"validatePaymasterTransaction","inputs": [{"name": "version","type": "uint256"},{"name": "txHash","type": "bytes32"},{"name": "transaction","type": "bytes"}]}
	]`

	validateTransactionAbi, _ := abi.JSON(strings.NewReader(jsondata))
	txAbiEncoding, _ := tx.AbiEncode()
	data, err := validateTransactionAbi.Pack("validatePaymasterTransaction", big.NewInt(1), signingHash, txAbiEncoding)

	if err != nil {
		return nil, err
	}
	return &Message{
		From:              EntryPointAddress,
		To:                &paymasterAddress,
		Value:             big.NewInt(0),
		GasLimit:          tx.PaymasterGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              data,
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		// IsRip7560Frame:    true,
	}, nil
}

func prepareAccountExecutionMessage(_ *params.ChainConfig, baseTx *types.Transaction) *Message {
	tx := baseTx.Rip7560TransactionData()
	return &Message{
		From:              EntryPointAddress,
		To:                tx.Sender,
		Value:             big.NewInt(0),
		GasLimit:          tx.Gas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              tx.Data,
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		// IsRip7560Frame:    true,
	}
}

func preparePostOpMessage(_ *params.ChainConfig, vpr *ValidationPhaseResult, executionResult *ExecutionResult) (*Message, error) {
	if len(vpr.PaymasterContext) == 0 {
		return nil, nil
	}

	tx := vpr.Tx.Rip7560TransactionData()
	jsondata := `[
		{"type":"function","name":"postPaymasterTransaction","inputs": [{"name": "success","type": "bool"},{"name": "actualGasCost","type": "uint256"},{"name": "context","type": "bytes"}]}
	]`
	postPaymasterTransactionAbi, err := abi.JSON(strings.NewReader(jsondata))
	if err != nil {
		return nil, err
	}
	postOpData, err := postPaymasterTransactionAbi.Pack("postPaymasterTransaction", true, big.NewInt(0), vpr.PaymasterContext)
	if err != nil {
		return nil, err
	}
	var paymasterAddress common.Address = [20]byte(tx.PaymasterData[0:20])
	return &Message{
		From:              EntryPointAddress,
		To:                &paymasterAddress,
		Value:             big.NewInt(0),
		GasLimit:          tx.PaymasterGas - executionResult.UsedGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              postOpData,
		AccessList:        tx.AccessList,
		SkipAccountChecks: true,
		// IsRip7560Frame:    true,
	}, nil
}

func validateAccountReturnData(data []byte) (uint64, uint64, error) {
	var MAGIC_VALUE_SENDER = [20]byte{0xbf, 0x45, 0xc1, 0x66}
	if len(data) != 32 {
		return 0, 0, errors.New("invalid account return data length")
	}
	// when estimate gas, skip check

	magicExpected := common.Bytes2Hex(data[:20])
	if magicExpected != common.Bytes2Hex(MAGIC_VALUE_SENDER[:]) {
		log.Error("[RIP-7560] validateAccountReturnData invalid MAGIC_VALUE", "receive", magicExpected, "MAGIC_VALUE_SENDER", common.Bytes2Hex(MAGIC_VALUE_SENDER[:]))

		return 0, 0, errors.New("account did not return correct MAGIC_VALUE")
	}

	validUntil := binary.BigEndian.Uint64(data[4:12])
	validAfter := binary.BigEndian.Uint64(data[12:20])
	return validAfter, validUntil, nil
}

func validatePaymasterReturnData(data []byte) ([]byte, uint64, uint64, error) {
	var MAGIC_VALUE_PAYMASTER = [20]byte{0xe0, 0xe6, 0x18, 0x3a}
	jsondata := `[
		{"type": "function","name": "validatePaymasterTransaction","outputs": [{"name": "validationData","type": "bytes32"},{"name": "context","type": "bytes"}]}
	]`
	validatePaymasterTransactionAbi, err := abi.JSON(strings.NewReader(jsondata))
	if err != nil {
		// TODO: wrap error message
		return nil, 0, 0, err
	}

	var validatePaymasterResult struct {
		ValidationData [32]byte
		Context        []byte
	}

	err = validatePaymasterTransactionAbi.UnpackIntoInterface(&validatePaymasterResult, "validatePaymasterTransaction", data)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(validatePaymasterResult.Context) > MaxContextSize {
		return nil, 0, 0, errors.New("paymaster returned context size too large")
	}

	magicExpected := common.Bytes2Hex(validatePaymasterResult.ValidationData[:20])
	if magicExpected != common.Bytes2Hex(MAGIC_VALUE_PAYMASTER[:]) {
		log.Error("[RIP-7560] validatePaymasterReturnData invalid MAGIC_VALUE", "receive", magicExpected, "MAGIC_VALUE_PAYMASTER", common.Bytes2Hex(MAGIC_VALUE_PAYMASTER[:]))
		return nil, 0, 0, errors.New("paymaster did not return correct MAGIC_VALUE")
	}

	validUntil := binary.BigEndian.Uint64(validatePaymasterResult.ValidationData[4:12])
	validAfter := binary.BigEndian.Uint64(validatePaymasterResult.ValidationData[12:20])
	context := validatePaymasterResult.Context

	return context, validAfter, validUntil, nil
}

func validateValidityTimeRange(time uint64, validAfter uint64, validUntil uint64) error {
	if validUntil == 0 && validAfter == 0 {
		return nil
	}
	if validUntil < validAfter {
		return errors.New("RIP-7560 transaction validity range invalid")
	}
	if time > validUntil {
		return errors.New("RIP-7560 transaction validity expired")
	}
	if time < validAfter {
		return errors.New("RIP-7560 transaction validity not reached yet")
	}
	return nil
}
