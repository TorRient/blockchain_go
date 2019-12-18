package main

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
)

const protocol = "tcp"
const nodeVersion = 1
const commandLength = 12

var nodeAddress string
var miningAddress string
var knownNodes = []string{"192.168.43.213:3000"}
var blocksInTransit = [][]byte{}
var mempool = make(map[string]Transaction)

type addr struct {
	AddrList []string
}

type block struct {
	AddrFrom string
	Block    []byte
}

type getblocks struct {
	AddrFrom string
}

// type numMines struct {
// 	AddrMine string
// 	Count    int
// 	CountAll int
// }

type getdata struct {
	AddrFrom string
	Type     string
	ID       []byte
}

type inv struct {
	AddrFrom string
	Type     string
	Items    [][]byte
}

type tx struct {
	AddFrom     string
	Transaction []byte
}

type verzion struct {
	Version    int
	BestHeight int
	AddrFrom   string
}

func commandToBytes(command string) []byte {
	var bytes [commandLength]byte

	for i, c := range command {
		bytes[i] = byte(c)
	}

	return bytes[:]
}

func bytesToCommand(bytes []byte) string {
	var command []byte

	for _, b := range bytes {
		if b != 0x0 {
			command = append(command, b)
		}
	}

	return fmt.Sprintf("%s", command)
}

func extractCommand(request []byte) []byte {
	return request[:commandLength]
}

func requestBlocks() {
	for _, node := range knownNodes {
		sendGetBlocks(node)
	}
}

func sendAddr(address string) {
	nodes := addr{knownNodes}
	nodes.AddrList = append(nodes.AddrList, nodeAddress)
	payload := gobEncode(nodes)
	request := append(commandToBytes("addr"), payload...)

	sendData(address, request)
}

func sendBlock(addr string, b *Block) {
	data := block{nodeAddress, b.Serialize()}
	payload := gobEncode(data)
	request := append(commandToBytes("block"), payload...)

	sendData(addr, request)
}

func sendData(addr string, data []byte) {
	conn, err := net.Dial(protocol, addr)
	if err != nil {
		fmt.Printf("%s is not available\n", addr)
		var updatedNodes []string

		for _, node := range knownNodes {
			if node != addr {
				updatedNodes = append(updatedNodes, node)
			}
		}

		knownNodes = updatedNodes

		return
	}
	defer conn.Close()

	_, err = io.Copy(conn, bytes.NewReader(data))
	if err != nil {
		log.Panic(err)
	}
}

func hand_balance1(bc *Blockchain) float64 {
	// if !ValidateAddress(miningAddress) {
	// 	log.Panic("ERROR: Address is not valid")
	// }
	UTXOSet := UTXOSet{bc}
	// defer bc.db.Close()

	balance_self := 0
	balance_total := 0
	pubKeyHash := Base58Decode([]byte(miningAddress))
	log.Print(miningAddress)
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-4]

	UTXOs_self := UTXOSet.FindUTXO(pubKeyHash)
	for _, out := range UTXOs_self {
		balance_self += out.Value
	}
	fmt.Printf("Balance of '%s': %d\n", miningAddress, balance_self)

	UTXOs_total := UTXOSet.FindAllUTXO()
	for _, out := range UTXOs_total {
		balance_total += out.Value
	}
	lol := float64(balance_self) / float64(balance_total)
	fmt.Printf("Balance of total: %v\n", lol)
	return lol
}

func hand_balance2(bc *Blockchain, from string) float64 {
	// if !ValidateAddress(miningAddress) {
	// 	log.Panic("ERROR: Address is not valid")
	// }
	// var buff bytes.Buffer
	// var payload inv
	// buff.Write(request[commandLength:])
	// dec := gob.NewDecoder(&buff)
	// err := dec.Decode(&payload)
	// if err != nil {
	// 	log.Panic(err)
	// }

	UTXOSet := UTXOSet{bc}
	// defer bc.db.Close()

	balance_self := 0
	balance_total := 0
	// count := 0
	// countAll := 0
	// countAll := len(payload.Items)
	pubKeyHash := Base58Decode([]byte(from))
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-4]

	UTXOs_self := UTXOSet.FindUTXO(pubKeyHash)
	for _, out := range UTXOs_self {
		balance_self += out.Value
	}

	fmt.Printf("Balance of '%s': %d\n", from, balance_self)

	UTXOs_total := UTXOSet.FindAllUTXO()
	for _, out := range UTXOs_total {
		balance_total += out.Value
	}

	lol := float64(balance_self) / float64(balance_total)
	// percentMine := float64(count) / float64(countAll)
	// fmt.Printf(string(countAll))
	fmt.Printf("Balance of total: %v\n", lol)
	return lol
}

func handleMines(bc *Blockchain, from string) float64 {
	// cbTx := NewCoinbaseTX(from, "")
	// for _, input := range cbTx.Vin {
	// 	if input.Vout == -1 {
	// 		num.Count++
	// 		num.CountAll++
	// 	}
	// }

	countAll := 0
	count := 0
	bci := bc.Iterator()

	pubKeyHash := Base58Decode([]byte(from))
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-4]

	for {
		block := bci.Next()
		// flag := 0

		// fmt.Printf("============ Block %x ============\n", block.Hash)
		// fmt.Printf("Height: %d\n", block.Height)
		// fmt.Printf("Prev. block: %x\n", block.PrevBlockHash)
		// pow := NewProofOfWork(block)
		// fmt.Printf("PoW: %s\n\n", strconv.FormatBool(pow.Validate()))
		countAll++

		for _, tx := range block.Transactions {
			// fmt.Println(tx)
			var lines []string
			lines = append(lines, fmt.Sprintf("--- Transaction %x:", tx.ID))

			for i, input := range tx.Vin {

				lines = append(lines, fmt.Sprintf("     Input %d:", i))
				lines = append(lines, fmt.Sprintf("       TXID:      %x", input.Txid))
				lines = append(lines, fmt.Sprintf("       Out:       %d", input.Vout))
				lines = append(lines, fmt.Sprintf("       Signature: %x", input.Signature))
				lines = append(lines, fmt.Sprintf("       PubKey:    %x", input.PubKey))

				for i, output := range tx.Vout {
					lines = append(lines, fmt.Sprintf("     Output %d:", i))
					lines = append(lines, fmt.Sprintf("       Value:  %d", output.Value))
					lines = append(lines, fmt.Sprintf("       Script: %x", output.PubKeyHash))
					if input.Vout == -1 {
						if string(output.PubKeyHash) == string(pubKeyHash) {
							count++
						}
					}
				}
			}
		}

		// 	if i == 1 && string(pubKeyHash) == string(output.PubKeyHash) && flag == 0 {
		// 		count++
		// 		flag = 1
		// 	}
		// }

		// output := tx.Vout[len(tx.Vout)-1]
		// // lines = append(lines, fmt.Sprintf("     Output %d:", i))
		// lines = append(lines, fmt.Sprintf("       Value:  %d", output.Value))
		// lines = append(lines, fmt.Sprintf("       Script: %x", output.PubKeyHash))

		// if string(pubKeyHash) == string(output.PubKeyHash) && flag == 0 {
		// 	count++
		// 	flag = 1
		// }

		// return strings.Join(lines, "\n")
		// var linesString = strings.Join(lines, " ")
		// if strings.Contains(linesString, string(pubKeyHash)) {
		// 	count++
		// }
		// log.Printf("Trans: %s", lines)

		fmt.Printf("\n\n")

		if len(block.PrevBlockHash) == 0 {
			break
		}
	}

	log.Printf("Mined: %d\n", count)
	log.Printf("Total mined: %d\n", countAll)
	percentMine := float64(count) / float64(countAll)
	log.Printf("Percent of mine: %v", percentMine)

	return percentMine
}

func sendInv(address, kind string, items [][]byte) {
	inventory := inv{nodeAddress, kind, items}
	payload := gobEncode(inventory)
	request := append(commandToBytes("inv"), payload...)

	sendData(address, request)
}

func sendGetBlocks(address string) {
	payload := gobEncode(getblocks{nodeAddress})
	request := append(commandToBytes("getblocks"), payload...)

	sendData(address, request)
}

func sendGetData(address, kind string, id []byte) {
	payload := gobEncode(getdata{nodeAddress, kind, id})
	request := append(commandToBytes("getdata"), payload...)

	sendData(address, request)
}

func sendTx(addr string, tnx *Transaction) {
	data := tx{nodeAddress, tnx.Serialize()}
	log.Printf(nodeAddress + "AAAAAAAAA")
	log.Printf(string(nodeAddress))
	log.Printf(addr + "BBBBBBBBBBBBB")
	payload := gobEncode(data)
	request := append(commandToBytes("tx"), payload...)

	sendData(addr, request)
}

func sendVersion(addr string, bc *Blockchain) {
	bestHeight := bc.GetBestHeight()
	payload := gobEncode(verzion{nodeVersion, bestHeight, nodeAddress})

	request := append(commandToBytes("version"), payload...)

	sendData(addr, request)
}

func handleAddr(request []byte) {
	var buff bytes.Buffer
	var payload addr

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	knownNodes = append(knownNodes, payload.AddrList...)
	fmt.Printf("There are %d known nodes now!\n", len(knownNodes))
	requestBlocks()
}

func handleBlock(request []byte, bc *Blockchain) {
	var buff bytes.Buffer
	var payload block

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	blockData := payload.Block
	block := DeserializeBlock(blockData)

	fmt.Println("Recevied a new block!")
	bc.AddBlock(block)

	fmt.Printf("Added block %x\n", block.Hash)

	if len(blocksInTransit) > 0 {
		blockHash := blocksInTransit[0]
		sendGetData(payload.AddrFrom, "block", blockHash)

		blocksInTransit = blocksInTransit[1:]
	} else {
		UTXOSet := UTXOSet{bc}
		UTXOSet.Reindex()
	}
}

func handleInv(request []byte, bc *Blockchain) {
	var buff bytes.Buffer
	var payload inv

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	fmt.Printf("Recevied inventory with %d %s\n", len(payload.Items), payload.Type)

	if payload.Type == "block" {
		blocksInTransit = payload.Items

		blockHash := payload.Items[0]
		sendGetData(payload.AddrFrom, "block", blockHash)

		newInTransit := [][]byte{}
		for _, b := range blocksInTransit {
			if bytes.Compare(b, blockHash) != 0 {
				newInTransit = append(newInTransit, b)
			}
		}
		blocksInTransit = newInTransit
	}

	if payload.Type == "tx" {
		txID := payload.Items[0]

		if mempool[hex.EncodeToString(txID)].ID == nil {
			sendGetData(payload.AddrFrom, "tx", txID)
		}
	}
}

func handleGetBlocks(request []byte, bc *Blockchain) {
	var buff bytes.Buffer
	var payload getblocks

	log.Println("AAAAAAAAAAAAAAAAAAAAAAAAA")
	log.Println(payload.AddrFrom + "HAHA")
	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	blocks := bc.GetBlockHashes()
	sendInv(payload.AddrFrom, "block", blocks)
}

func handleGetData(request []byte, bc *Blockchain) {
	var buff bytes.Buffer
	var payload getdata

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	if payload.Type == "block" {
		block, err := bc.GetBlock([]byte(payload.ID))
		if err != nil {
			return
		}

		sendBlock(payload.AddrFrom, &block)
	}

	if payload.Type == "tx" {
		txID := hex.EncodeToString(payload.ID)
		tx := mempool[txID]

		sendTx(payload.AddrFrom, &tx)
		// delete(mempool, txID)
	}
}

func handleTx(request []byte, bc *Blockchain) {
	var buff bytes.Buffer
	var payload tx
	// var flag int

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	txData := payload.Transaction
	tx := DeserializeTransaction(txData)
	mempool[hex.EncodeToString(tx.ID)] = tx

	// if nodeAddress == knownNodes[0] {
	// 	for _, node := range knownNodes {
	// 		flag = 0
	// 		for id := range mempool {
	// 			tx := mempool[id]
	// 			if bc.VerifyTransaction(&tx) {
	// 				sendVersion(payload.AddFrom, bc)
	// 				flag = 1
	// 				break
	// 			}
	// 		}
	// 		if node != nodeAddress && node != payload.AddFrom && flag == 0 {
	// 			sendInv(node, "tx", [][]byte{tx.ID})
	// 		}
	// 	}
	// }

	if nodeAddress == knownNodes[0] {
		for _, node := range knownNodes {
			if node != nodeAddress && node != payload.AddFrom {
				sendInv(node, "tx", [][]byte{tx.ID})
			}
		}
	} else {
		if len(mempool) >= 1 && len(miningAddress) > 0 {
		MineTransactions:
			var txs []*Transaction

			for id := range mempool {
				tx := mempool[id]
				if bc.VerifyTransaction(&tx) {
					txs = append(txs, &tx)
				}
			}

			if len(txs) == 0 {
				fmt.Println("All transactions are invalid! Waiting for new ones...")
				return
			}

			cbTx := NewCoinbaseTX(miningAddress, "")
			txs = append(txs, cbTx)

			newBlock := bc.MineBlock(txs, miningAddress)
			UTXOSet := UTXOSet{bc}
			UTXOSet.Update(newBlock)

			fmt.Println("New block is mined!")

			for _, tx := range txs {
				txID := hex.EncodeToString(tx.ID)
				delete(mempool, txID)
			}

			for _, node := range knownNodes {
				if node != nodeAddress {
					sendInv(node, "block", [][]byte{newBlock.Hash})
				}
			}

			// sendInv(knownNodes[0], "block", [][]byte{newBlock.Hash})

			if len(mempool) > 0 {
				goto MineTransactions
			}
		}
	}
}

func handleVersion(request []byte, bc *Blockchain) {
	var buff bytes.Buffer
	var payload verzion

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	myBestHeight := bc.GetBestHeight()
	foreignerBestHeight := payload.BestHeight

	if myBestHeight < foreignerBestHeight {
		sendGetBlocks(payload.AddrFrom)
	} else if myBestHeight > foreignerBestHeight {
		sendVersion(payload.AddrFrom, bc)
	}

	// sendAddr(payload.AddrFrom)
	if !nodeIsKnown(payload.AddrFrom) {
		knownNodes = append(knownNodes, payload.AddrFrom)
	}
}

func handleConnection(conn net.Conn, bc *Blockchain) {
	request, err := ioutil.ReadAll(conn)
	if err != nil {
		log.Panic(err)
	}
	command := bytesToCommand(request[:commandLength])
	fmt.Printf("Received %s command\n", command)

	switch command {
	case "addr":
		handleAddr(request)
	case "block":
		handleBlock(request, bc)
	case "inv":
		handleInv(request, bc)
	case "getblocks":
		handleGetBlocks(request, bc)
	case "getdata":
		handleGetData(request, bc)
	case "tx":
		handleTx(request, bc)
	case "version":
		handleVersion(request, bc)
	default:
		fmt.Println("Unknown command!")
	}

	conn.Close()
}

// StartServer starts a node
func StartServer(nodeID, minerAddress string) {
	nodeAddress = fmt.Sprintf("192.168.43.213:%s", nodeID)
	miningAddress = minerAddress
	ln, err := net.Listen(protocol, nodeAddress)
	if err != nil {
		log.Panic(err)
	}
	defer ln.Close()

	bc := NewBlockchain(nodeID)

	if nodeAddress != knownNodes[0] {
		sendVersion(knownNodes[0], bc)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Panic(err)
		}
		go handleConnection(conn, bc)
	}
}

func gobEncode(data interface{}) []byte {
	var buff bytes.Buffer

	enc := gob.NewEncoder(&buff)
	err := enc.Encode(data)
	if err != nil {
		log.Panic(err)
	}

	return buff.Bytes()
}

func nodeIsKnown(addr string) bool {
	for _, node := range knownNodes {
		if node == addr {
			return true
		}
	}

	return false
}
