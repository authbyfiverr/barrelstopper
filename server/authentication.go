package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

func getInput(h string, eUUID string, av string) string {
	offset, _ := strconv.Atoi(av)

	// The last digit of h
	val, _ := strconv.Atoi(string(h[10]))

	var L []string
	if val > 5 {
		// No occurrence of e
		for _, c := range h[:10] {
			index, _ := strconv.Atoi(string(c))
			L = append(L, UUIDs[index+offset])
		}
	} else if val > 0 {
		// 1 occurrence of e
		for _, c := range h[:10] {
			index, _ := strconv.Atoi(string(c))
			L = append(L, UUIDs[index+offset])
		}
		index, _ := strconv.Atoi(string(h[len(h)-1]))
		L[index] = eUUID
	} else {
		// Multiple occurrences of e
		for _, c := range h[:10] {
			index, _ := strconv.Atoi(string(c))
			L = append(L, UUIDs[index+offset])
		}
		L[0] = eUUID
		L[len(L)-1] = eUUID
		L[len(L)-2] = eUUID
		L[len(L)-3] = eUUID
		L[len(L)-4] = eUUID
	}

	return strings.Join(L, "")
}

func computeHash(h string, eUUID string, av string) string {
	to_hash := getInput(h, eUUID, av)
	_h := sha256.New()
	_h.Write([]byte(to_hash))
	return hex.EncodeToString(_h.Sum(nil))
}
