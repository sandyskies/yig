package iam

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/journeymidnight/yig/circuitbreak"
	"github.com/journeymidnight/yig/helper"
	"io/ioutil"
	"net/http"
	"strings"
)

// credential container for access and secret keys.
type Credential struct {
	UserId          string
	DisplayName     string
	AccessKeyID     string
	SecretAccessKey string
	Acl             string
	Status          string
}

func (a Credential) String() string {
	accessStr := "AccessKey: " + a.AccessKeyID
	secretStr := "SecretKey: " + a.SecretAccessKey
	return accessStr + " " + secretStr + "\n"
}

type AccessKeyItem struct {
	ProjectId    string `json:"projectId"`
	ProjectName  string `json:"projectName"`
	AccessKey    string `json:"accessKey"`
	AccessSecret string `json:"accessSecret"`
	Acl          string `json:"acl"`
	Status       string `json:"status"`
	Updated      string `json:"updated"`
}

type Query struct {
	ProjectId  string   `json:"projectId,omitempty"`
	AccessKey  string   `json:"accessKeys,omitempty"`
	//	Limit      int      `json:"limit"`
}

type QueryResp struct {
	AccessKeySet []AccessKeyItem `json:"accessKeySet"`
}

var iamClient *circuitbreak.CircuitClient

func GetKeysByUid(uid string) (keyslist []AccessKeyItem, err error) {

	var slog = helper.Logger
	var query Query
	if iamClient == nil {
		iamClient = circuitbreak.NewCircuitClient()
	}
	query.ProjectId = uid

	b, err := json.Marshal(query)
	if err != nil {
		slog.Println(5, "json err:", err)
		return keyslist, err
	}
	request, _ := http.NewRequest("POST", helper.CONFIG.IamEndpoint, strings.NewReader(string(b)))
	request.Header.Set("X-Le-Key", "key")
	request.Header.Set("X-Le-Secret", "secret")
	slog.Println(10, "replay request:", request, string(b))
	response, err := iamClient.Do(request)
	if err != nil {
		slog.Println(5, "replay histroy send request failed", err)
		return keyslist, err
	}

	if response.StatusCode != 200 {
		slog.Println(5, "QueryHistory to IAM failed as status != 200")
		return keyslist, fmt.Errorf("QueryHistory to IAM failed as status != 200")
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		slog.Println(5, "QueryHistory ioutil.ReadAll failed")
		return keyslist, fmt.Errorf("QueryHistory ioutil.ReadAll failed")
	}

	var queryResp QueryResp
	err = json.Unmarshal(body, &queryResp)
	if err != nil {
		return keyslist, errors.New("Decode QueryResp failed")
	}

	for _, value := range queryResp.AccessKeySet {
		keyslist = append(keyslist, value)
	}
	return keyslist, nil
}
