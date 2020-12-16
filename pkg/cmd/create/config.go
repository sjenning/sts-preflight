package create

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"path/filepath"
)

const (
	stateFile = "state.json"
)

type Config struct {
	InfraName               string
	Region                  string
	CredentialsRequestsFile string
	TargetDir               string
}

type State struct {
	InfraName string `json:"infraName"`
	Region    string `json:"region"`
	Kid       string `json:"kid"`
	RoleARN   string `json:"roleARN"`
	TargetDir string `json:"targetDir"`
}

func (s *State) Write() {
	jsonBytes, err := json.Marshal(s)
	if err != nil {
		log.Fatal(err)
	}

	stateFilePath := filepath.Join(s.TargetDir, stateFile)
	err = ioutil.WriteFile(stateFilePath, jsonBytes, 0600)
	if err != nil {
		log.Fatal(err)
	}
}

func (s *State) Read() {
	stateFilePath := filepath.Join(s.TargetDir, stateFile)
	jsonBytes, err := ioutil.ReadFile(stateFilePath)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(jsonBytes, s)
	if err != nil {
		log.Fatal(err)
	}
}
