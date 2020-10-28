package create

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

const (
	stateFile = "_output/state.json"
)

type Config struct {
	InfraName string
	Region    string
}

type State struct {
	InfraName string `json:"infraName"`
	Region    string `json:"region"`
	Kid       string `json:"kid"`
	RoleARN   string `json:"roleARN"`
}

func (s *State) Write() {
	jsonBytes, err := json.Marshal(s)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(stateFile, jsonBytes, 0600)
	if err != nil {
		log.Fatal(err)
	}
}

func (s *State) Read() {
	jsonBytes, err := ioutil.ReadFile(stateFile)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(jsonBytes, s)
	if err != nil {
		log.Fatal(err)
	}
}
