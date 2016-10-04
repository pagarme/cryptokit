package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/pagarme/cryptokit/soft/dukpt"
	"github.com/tucnak/climax"
)

func main() {
	app := climax.New("dukpt")

	app.AddCommand(climax.Command{
		Name:   "bdk_kcv",
		Handle: derivedBdkKcv,
	})

	app.AddCommand(climax.Command{
		Name:   "derived_bdk_kcv",
		Handle: derivedBdkKcv,
	})

	app.Run()
}

func bdkKcv(ctx climax.Context) int {
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

func derivedBdkKcv(ctx climax.Context) int {
	bdk, err := deriveBdk()

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return -1
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

func deriveBdk() ([]byte, error) {
	count := 1
	bdk := make([]byte, 16)

	for true {
		fmt.Printf("Enter key part #%d (empty to end): ", count)
		part, err := askHex()

		if part == nil {
			break
		}

		if err != nil {
			return nil, err
		}

		if len(part) != 16 {
			return nil, errors.New("Key tool small")
		}

		fmt.Printf("Enter key part #%d KCV: ", count)
		kcv, err := askHex()

		if kcv == nil || err != nil {
			return nil, err
		}

		computedKcv, err := dukpt.CalculateKcv(part)

		if !compareKcv(kcv, computedKcv) {
			return nil, errors.New("Keys doesn't match")
		}

		if err != nil {
			return nil, err
		}

		for i, v := range part {
			bdk[i] ^= v
		}

		count++
	}

	return bdk, nil
}

func askHex() ([]byte, error) {
	str := ""

	fmt.Scanf("%s\n", &str)

	if str == "" {
		return nil, nil
	}

	return hex.DecodeString(str)
}

func compareKcv(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}

	return true
}
