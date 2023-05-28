package main

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
)

type SnapResponseApi struct {
	ResponseCode    string      `json:"responseCode"`
	ResponseMessage string      `json:"responseMessage"`
	Data            interface{} `json:"data,omitempty"`
}

func SnapResponse(w http.ResponseWriter, req interface{}) {
	statCode := SnapResponseApi{}

	reqByte, err := json.Marshal(req)
	if err != nil {
		w.Write(reqByte)
	}

	if err := json.Unmarshal(reqByte, &statCode); err != nil {
		w.Write(reqByte)
	}

	if reflect.DeepEqual(statCode, SnapResponseApi{}) {
		statCode.ResponseCode = "5000000"
		statCode.ResponseMessage = "General Error"
	} else if statCode.ResponseCode == "" || statCode.ResponseMessage == "" {
		statCode.ResponseCode = "4000000"
		statCode.ResponseMessage = "Bad Request"
	}

	code, err := strconv.Atoi(statCode.ResponseCode[0:3])
	if err != nil {
		w.Write(reqByte)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(reqByte)
}
