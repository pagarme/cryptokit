package main

import (
	"encoding/hex"
	"fmt"
	"github.com/pagarme/cryptokit/soft/dukpt"
	"github.com/tucnak/climax"
)

func main() {
	app := climax.New("dukpt")

	app.AddCommand(climax.Command{
		Name:   "bdk_part_kcv",
		Handle: bdkPartKcv,
	})

	app.AddCommand(climax.Command{
		Name:   "bdk_kcv",
		Handle: bdkKcv,
	})

	app.AddCommand(climax.Command{
		Name:   "ipek_kcv",
		Handle: ipekKcv,
	})

	app.Run()
}

func bdkPartKcv(ctx climax.Context) int {
	fmt.Printf("Enter key part: ")
	part, err := askHex()

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return -1
	}

	if len(part) != 16 {
		fmt.Printf("Key too small\n")
		return -1
	}

	kcv, err := dukpt.CalculateKcv(part)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return -1
	}

	kcvStr := hex.EncodeToString(kcv)

	fmt.Printf("KCV: %s\n", kcvStr)

	return 0
}

func bdkKcv(ctx climax.Context) int {
	count := 1
	bdk := make([]byte, 16)

	for true {
		fmt.Printf("Enter key part #%d (empty to end): ", count)
		part, err := askHex()

		if part == nil {
			break
		}

		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return -1
		}

		if len(part) != 16 {
			fmt.Printf("Key too small\n")
			return -1
		}

		for i, v := range part {
			bdk[i] ^= v
		}

		count++
	}

	kcv, err := dukpt.CalculateKcv(bdk)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return -1
	}

	kcvStr := hex.EncodeToString(kcv)

	fmt.Printf("BDK KCV: %s\n", kcvStr)

	return 0
}

func ipekKcv(ctx climax.Context) int {
	count := 1
	bdk := make([]byte, 16)

	fmt.Printf("Enter KSN: ")
	ksn, err := askHex()

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return -1
	}

	if len(ksn) != 10 {
		fmt.Printf("Invalid KSN size\n")
		return -1
	}

	for true {
		fmt.Printf("Enter key part #%d (empty to end): ", count)
		part, err := askHex()

		if part == nil {
			break
		}

		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return -1
		}

		if len(part) != 16 {
			fmt.Printf("Key too small\n")
			return -1
		}

		for i, v := range part {
			bdk[i] ^= v
		}

		count++
	}

	ipek, err := dukpt.DeriveIpekFromBdk(bdk, ksn)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return -1
	}

	kcv, err := dukpt.CalculateKcv(ipek)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return -1
	}

	kcvStr := hex.EncodeToString(kcv)

	fmt.Printf("IPEK KCV: %s\n", kcvStr)

	return 0
}

func askHex() ([]byte, error) {
	str := ""

	fmt.Scanf("%s\n", &str)

	if str == "" {
		return nil, nil
	}

	return hex.DecodeString(str)
}
