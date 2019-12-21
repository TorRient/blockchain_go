package main

import (
	"fmt"
	"strconv"
)

func (cli *CLI) printChain(nodeID string) {
	// var data [][]string
	bc := NewBlockchain(nodeID)
	defer bc.db.Close()

	bci := bc.Iterator()

	for {
		block := bci.Next()

		fmt.Printf("============ Block %x ============\n", block.Hash)
		fmt.Printf("Height: %d\n", block.Height)
		fmt.Printf("Prev. block: %x\n", block.PrevBlockHash)
		pow := NewProofOfWork(block)
		fmt.Printf("PoW: %s\n\n", strconv.FormatBool(pow.Validate()))
		for _, tx := range block.Transactions {
			fmt.Println(tx)
		}
		fmt.Printf("\n\n")

		if len(block.PrevBlockHash) == 0 {
			break
		}
	}

	// data = csvExport(nodeID)
	// data = append(data, []string{"s", "z"})
	// dataString := strings.Join(data, " ")
	// log.Printf(dataString)

	//Write to csv
	// file, err := os.Create("result.csv")
	// if err != nil {
	// 	return err
	// }
	// defer file.Close()

	// writer := csv.NewWriter(file)
	// defer writer.Flush()

	// for _, value := range data {
	// 	if err := writer.Write(value); err != nil {
	// 		return err
	// 	}
	// }
	// return nil
}
