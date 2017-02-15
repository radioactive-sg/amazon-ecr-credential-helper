// Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package ecr

import (
	// "encoding/json"
	"errors"
	// "io/ioutil"
	"regexp"

	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"

	"github.com/awslabs/amazon-ecr-credential-helper/ecr-login/api"
	log "github.com/cihub/seelog"
	"github.com/docker/docker-credential-helpers/credentials"
)

const programName = "docker-credential-ecr-login"

var ecrPattern = regexp.MustCompile(`(^[a-zA-Z0-9][a-zA-Z0-9-_]*)\.dkr\.ecr\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.amazonaws\.com(\.cn)?`)
var notImplemented = errors.New("not implemented")

type ECRHelper struct {
	ClientFactory api.ClientFactory
}

func (ECRHelper) Add(creds *credentials.Credentials) error {
	// This does not seem to get called
	return notImplemented
}

func (ECRHelper) Delete(serverURL string) error {
	// This does not seem to get called
	return notImplemented
}

type DockerAuthItem struct {
	Auth string
}

type DockerAuth struct {
	Auths map[string]DockerAuthItem
}

func ExtractDockerAuth(data []byte, url string) (string, string, error) {
	res := DockerAuth{}
	err := json.Unmarshal(data, &res)
	if err != nil {
		log.Error("unable to decode config from json")
		return "", "", err
	}
	for host, auth := range res.Auths {
		if strings.Contains(url, host) {
			decodedBytes, err := base64.StdEncoding.DecodeString(auth.Auth)
			if err != nil {
				log.Error("unable to decode auth as b64")
				return "", "", err
			}
			decodedStrings := strings.Split(string(decodedBytes), ":")
			if len(decodedStrings) != 2 {
				log.Error("bad format of auth")
				return "", "", errors.New("bad format of auth")
			}
			return decodedStrings[0], decodedStrings[1], nil
		}
	}
	return "", "", errors.New(url + " not found")
}

func getDockerConfig() ([]byte, error) {
	home := os.Getenv("HOME")
	if home == "" {
		log.Error("user home not found")
	}
	return ioutil.ReadFile(home + "/.docker/config.json")
}

func getDockerAuth(serverUrl string) (string, string, error) {
	dat, err := getDockerConfig()
	if err != nil {
		log.Error("docker config not found")
		return "", "", err
	}
	return ExtractDockerAuth(dat, serverUrl)
}

func (self ECRHelper) Get(serverURL string) (string, string, error) {
	defer log.Flush()
	user, pass, err := getDockerAuth(serverURL)
	if err == nil {
		return user, pass, err
	}

	matches := ecrPattern.FindStringSubmatch(serverURL)
	if len(matches) == 0 {
		log.Error(programName + " can only be used with Amazon EC2 Container Registry.")
		return "", "", credentials.ErrCredentialsNotFound
	} else if len(matches) < 3 {
		log.Error(serverURL + "is not a valid repository URI for Amazon EC2 Container Registry.")
		return "", "", credentials.ErrCredentialsNotFound
	}

	registry := matches[1]
	region := matches[2]
	log.Debugf("Retrieving credentials for %s in %s (%s)", registry, region, serverURL)
	client := self.ClientFactory.NewClient(region)
	user, pass, err = client.GetCredentials(registry, serverURL)
	if err != nil {
		log.Errorf("Error retrieving credentials: %v", err)
		return "", "", credentials.ErrCredentialsNotFound
	}
	return user, pass, nil
}
