package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
)

type metadata struct {
	Name     string `json:"name"`
	Weight   int    `json:"weight"`
	HashAlgo string `json:"hash_algo"`
	KeyAlgo  string `json:"key_algo"`
	Keystore string `json:"keystore"`
}

var metadataFiles = []string{
	"ca-bundle.crt.metadata",
}

func TestMetadataFormat(t *testing.T) {
	for _, file := range metadataFiles {
		in, err := ioutil.ReadFile(file)
		if err != nil {
			t.Fatalf("%v", err)
		}

		// Ensure the metadata is well-formatted JSON.
		var ms []metadata
		err = json.Unmarshal(in, &ms)
		if err != nil {
			t.Fatalf("%v", err)
		}

		for _, m := range ms {
			// Ensure the metadata points to a valid keystore.
			if m.Keystore != "" {
				_, err = os.Stat(m.Keystore)
				if err != nil {
					t.Fatalf("%v", err)
				}
			}
		}
	}
}
