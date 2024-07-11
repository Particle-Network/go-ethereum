// Copyright 2021 The go-ethereum Authors
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

package types

import (
	"bytes"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
)

// Rip7560BundleHeaderTx represents an RIP-7560 bundle header transaction.
type Rip7560BundleHeaderTx struct {
	ChainID          *big.Int
	BlockNumber      *big.Int
	TransactionCount uint64
	TransactionIndex uint64
}

// accessors for innerTx.
func (tx *Rip7560BundleHeaderTx) txType() byte           { return Rip7560BundleHeaderType }
func (tx *Rip7560BundleHeaderTx) chainID() *big.Int      { return tx.ChainID }
func (tx *Rip7560BundleHeaderTx) accessList() AccessList { return nil }
func (tx *Rip7560BundleHeaderTx) data() []byte           { return nil }
func (tx *Rip7560BundleHeaderTx) gas() uint64            { return 0 }
func (tx *Rip7560BundleHeaderTx) gasFeeCap() *big.Int    { return new(big.Int) }
func (tx *Rip7560BundleHeaderTx) gasTipCap() *big.Int    { return new(big.Int) }
func (tx *Rip7560BundleHeaderTx) gasPrice() *big.Int     { return new(big.Int) }
func (tx *Rip7560BundleHeaderTx) value() *big.Int        { return new(big.Int) }
func (tx *Rip7560BundleHeaderTx) nonce() uint64          { return 0 }
func (tx *Rip7560BundleHeaderTx) to() *common.Address    { return nil }

func (tx *Rip7560BundleHeaderTx) isSystemTx() bool { return false }
func (tx *Rip7560BundleHeaderTx) copy() TxData {
	cpy := &Rip7560BundleHeaderTx{
		ChainID:          new(big.Int),
		BlockNumber:      new(big.Int),
		TransactionCount: 0,
		TransactionIndex: 0,
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.BlockNumber != nil {
		cpy.BlockNumber.Set(tx.BlockNumber)
	}
	if tx.TransactionCount != 0 {
		cpy.TransactionCount = tx.TransactionCount
	}
	if tx.TransactionIndex != 0 {
		cpy.TransactionIndex = tx.TransactionIndex
	}
	return cpy
}

func (tx *Rip7560BundleHeaderTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

func (tx *Rip7560BundleHeaderTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *Rip7560BundleHeaderTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return new(big.Int)
}
func (tx *Rip7560BundleHeaderTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, tx)
}

func (tx *Rip7560BundleHeaderTx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}
