package main

import (
	"bytes"
	"encoding/gob"
	"log"
	"time"
)

// Block represents a block in the blockchain
type Block struct {
	Timestamp     int64
	Transactions  []*Transaction
	PrevBlockHash []byte
	Hash          []byte
	Nonce         int
	Height        int
	Percent       float64
}

// NewBlock creates and returns Block
func NewBlock(transactions []*Transaction, prevBlockHash []byte, height int, percent float64) *Block {
	block := &Block{time.Now().Unix(), transactions, prevBlockHash, []byte{}, 0, height, percent}
	pow := NewProofOfWork(block)
	log.Print("come here13")
	nonce, hash := pow.Run()

	block.Hash = hash[:]
	block.Nonce = nonce

	return block
}

// NewGenBlock creates and returns Block
func NewGenBlock(transactions []*Transaction, prevBlockHash []byte, height int) *Block {
	block := &Block{time.Now().Unix(), transactions, prevBlockHash, []byte{}, 0, height, 1}
	pow := NewGenProofOfWork(block)
	nonce, hash := pow.Run()

	block.Hash = hash[:]
	block.Nonce = nonce

	return block
}

// NewGenesisBlock creates and returns genesis Block
func NewGenesisBlock(coinbase *Transaction) *Block {
	return NewGenBlock([]*Transaction{coinbase}, []byte{}, 0)
}

// HashTransactions returns a hash of the transactions in the block
func (b *Block) HashTransactions() []byte {
	var transactions [][]byte

	for _, tx := range b.Transactions {
		transactions = append(transactions, tx.Serialize())
	}
	mTree := NewMerkleTree(transactions)

	return mTree.RootNode.Data
}

// Serialize serializes the block
func (b *Block) Serialize() []byte {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)

	err := encoder.Encode(b)
	if err != nil {
		log.Panic(err)
	}

	return result.Bytes()
}

// DeserializeBlock deserializes a block
func DeserializeBlock(d []byte) *Block {
	var block Block

	decoder := gob.NewDecoder(bytes.NewReader(d))
	err := decoder.Decode(&block)
	if err != nil {
		log.Panic(err)
	}

	return &block
}
