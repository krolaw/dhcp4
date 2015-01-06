// Simple tests for reflect helpers

package dhcp4

import (
	"testing"
	"encoding/json"
	"bytes"
	"reflect"
)


func TestJSONUnmarshal_optionsAll_byte_SubnetMask(t *testing.T){
	var opt optionsAll_byte
	optT, strO, byteV := &opt.SubnetMask, []byte(`{"SubnetMask":"255.255.255.0"}`), []byte{255,255,255,0}


	if err := json.Unmarshal(strO, &opt); err != nil {
		t.Fatal("Error in Unmarshal: ", err)
	}
	if !bytes.Equal(*optT, byteV) {
		t.Fatal(*optT, " != ", byteV)
	}
}

func TestJSONUnmarshal_optionsAll_byte_TimeOffset(t *testing.T){
	var opt optionsAll_byte
	optT, strO, byteV := &opt.TimeOffset, []byte(`{"TimeOffset":-124}`), []byte{255,255,255,132}


	if err := json.Unmarshal(strO, &opt); err != nil {
		t.Fatal("Error in Unmarshal: ", err)
	}
	if !bytes.Equal(*optT, byteV) {
		t.Fatal(*optT, " != ", byteV)
	}
}

func TestJSONUnmarshal_optionsAll_byte_Router(t *testing.T){
	var opt optionsAll_byte
	optT, strO, byteV := &opt.Router, []byte(`{"Router":["1.2.3.4","10.20.30.40"]}`), []byte{1,2,3,4,10,20,30,40}


	if err := json.Unmarshal(strO, &opt); err != nil {
		t.Fatal("Error in Unmarshal: ", err)
	}
	if !bytes.Equal(*optT, byteV) {
		t.Fatal(*optT, " != ", byteV)
	}
}

func TestJSONUnmarshal_optionsAll_byte_HostName(t *testing.T){
	var opt optionsAll_byte
	optT, strO, byteV := &opt.HostName, []byte(`{"HostName":"localhost"}`), []byte{'l','o','c','a','l','h','o','s','t'}


	if err := json.Unmarshal(strO, &opt); err != nil {
		t.Fatal("Error in Unmarshal: ", err)
	}
	if !bytes.Equal(*optT, byteV) {
		t.Fatal(*optT, " != ", byteV)
	}
}

func TestJSONUnmarshal_optionsAll_byte_BootFileSize(t *testing.T){
	var opt optionsAll_byte
	optT, strO, byteV := &opt.BootFileSize, []byte(`{"BootFileSize":124}`), []byte{0,124}


	if err := json.Unmarshal(strO, &opt); err != nil {
		t.Fatal("Error in Unmarshal: ", err)
	}
	if !bytes.Equal(*optT, byteV) {
		t.Fatal(*optT, " != ", byteV)
	}
}

func TestJSONUnmarshal_optionsAll_byte_IPForwardingEnableDisable(t *testing.T){
	var opt optionsAll_byte
	optT, strO, byteV := &opt.IPForwardingEnableDisable, []byte(`{"IPForwardingEnableDisable":true}`), []byte{1}


	if err := json.Unmarshal(strO, &opt); err != nil {
		t.Fatal("Error in Unmarshal: ", err)
	}
	if !bytes.Equal(*optT, byteV) {
		t.Fatal(*optT, " != ", byteV)
	}
}

func TestJSONUnmarshal_optionsAll_byte_PolicyFilter(t *testing.T){
	var opt optionsAll_byte
	optT, strO, byteV := &opt.PolicyFilter, []byte(`{"PolicyFilter":["1.2.3.4 255.255.255.0", "10.20.30.40 255.255.0.0"]}`),
		[]byte{1,2,3,4,255,255,255,0,10,20,30,40,255,255,0,0}


	if err := json.Unmarshal(strO, &opt); err != nil {
		t.Fatal("Error in Unmarshal: ", err)
	}
	if !bytes.Equal(*optT, byteV) {
		t.Fatal(*optT, " != ", byteV)
	}
}

func TestJSONUnmarshal_optionsAll_byte_DefaultIPTimeToLive(t *testing.T){
	var opt optionsAll_byte
	optT, strO, byteV := &opt.DefaultIPTimeToLive, []byte(`{"DefaultIPTimeToLive":124}`), []byte{124}


	if err := json.Unmarshal(strO, &opt); err != nil {
		t.Fatal("Error in Unmarshal: ", err)
	}
	if !bytes.Equal(*optT, byteV) {
		t.Fatal(*optT, " != ", byteV)
	}
}

func TestJSONUnmarshal_optionsAll_byte_PathMTUAgingTimeout(t *testing.T){
	var opt optionsAll_byte
	optT, strO, byteV := &opt.PathMTUAgingTimeout, []byte(`{"PathMTUAgingTimeout":124}`), []byte{0,0,0,124}


	if err := json.Unmarshal(strO, &opt); err != nil {
		t.Fatal("Error in Unmarshal: ", err)
	}
	if !bytes.Equal(*optT, byteV) {
		t.Fatal(*optT, " != ", byteV)
	}
}

func TestJSONUnmarshal_optionsAll_byte_PathMTUPlateauTable(t *testing.T){
	var opt optionsAll_byte
	optT, strO, byteV := &opt.PathMTUPlateauTable, []byte(`{"PathMTUPlateauTable":[1,2,4]}`), []byte{0,1,0,2,0,4}


	if err := json.Unmarshal(strO, &opt); err != nil {
		t.Fatal("Error in Unmarshal: ", err)
	}
	if !bytes.Equal(*optT, byteV) {
		t.Fatal(*optT, " != ", byteV)
	}
}

func TestJSONUnmarshal_Options(t *testing.T){
	var strO = []byte(`{
		"SubnetMask": "255.255.255.0",
		"TimeOffset": -124,
		"Router": ["1.2.3.4","10.20.30.40"],
		"HostName": "localhost",
		"BootFileSize": 124,
		"IPForwardingEnableDisable": true,
		"PolicyFilter": ["1.2.3.4 255.255.255.0", "10.20.30.40 255.255.0.0"],
		"DefaultIPTimeToLive": 124,
		"PathMTUAgingTimeout": 124,
		"PathMTUPlateauTable": [1,2,4]
	}`)
	var mapV = Options{
		OptionSubnetMask:                []byte{255,255,255,0},
		OptionTimeOffset:                []byte{255,255,255,132},
		OptionRouter:                    []byte{1,2,3,4,10,20,30,40},
		OptionHostName:                  []byte{'l','o','c','a','l','h','o','s','t'},
		OptionBootFileSize:              []byte{0,124},
		OptionIPForwardingEnableDisable: []byte{1},
		OptionPolicyFilter:              []byte{1,2,3,4,255,255,255,0,10,20,30,40,255,255,0,0},
		OptionDefaultIPTimeToLive:       []byte{124},
		OptionPathMTUAgingTimeout:       []byte{0,0,0,124},
		OptionPathMTUPlateauTable:       []byte{0,1,0,2,0,4},
	}

	var opt = Options{}

	if err := json.Unmarshal(strO, &opt); err != nil {
		t.Fatal("Error in Unmarshal: ", err)
	}
	if !reflect.DeepEqual(opt, mapV) {
		t.Fatal(opt, " != ", mapV)
	}
}