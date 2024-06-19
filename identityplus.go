package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

var verbose = false
var command = "get url"
var service = "identity.plus"
var authorization = ""
var managed_service = ""
var identity_dir = "."
var trust_store = ""
var url = ""

//
// just a set of wrappers around the methods
//
func do_get(endpoint string, request_body string, certificate string, key string) (string, []byte) {
	return do_call(endpoint, "GET", request_body, certificate, key)
}

func do_put(endpoint string, request_body string, certificate string, key string) (string, []byte) {
	return do_call(endpoint, "PUT", request_body, certificate, key)
}

func do_post(endpoint string, request_body string, certificate string, key string) (string, []byte) {
	return do_call(endpoint, "POST", request_body, certificate, key)
}

func do_delete(endpoint string, request_body string, certificate string, key string) (string, []byte) {
	return do_call(endpoint, "DELETE", request_body, certificate, key)
}

//
// returns 2 values int this order: the http response status (int) and the body of the answer ([]byte)
// - if the http response code is anything but 200, the body should be expected to contain
//   some error description
// - an error of 600 as response code means the call could not be made due to whatever reason
// - 5xx errors mean the request was made, but generated a server error
//
func do_call(endpoint string, method string, request_body string, certificate string, key string) (string, []byte) {

	client, err := client(certificate, key)

	if err != nil {
		return "Unable to create http client: " + err.Error(), nil
	}

	if verbose {
		fmt.Println(request_body)
	}

	// var body_reader io.Reader
	var jsonStr = []byte(request_body)
	client_request, err := http.NewRequest(method, endpoint, bytes.NewBuffer(jsonStr))
	client_request.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(client_request)

	defer func() {
		// only close body if it exists to prevent nil reference
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()

	if err != nil {
		return "error during https call: " + err.Error(), nil
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "error decoding https answer: " + err.Error(), nil
	}

	return "", bodyBytes
}

//
// Lazily creates a http client and caches it so that next time it does not have to create it
// also, this leverages re-use of TCP/TLS connection such that we do not have to do tripple
// handshake at every call
//
var __client *http.Client

func client(certificate string, key string) (*http.Client, error) {

	// create the client if not yet created
	if __client == nil {

		var client_certificates []tls.Certificate
		var trusted_authorities *x509.CertPool

		if trust_store != "" {
			root_cert, err := ioutil.ReadFile(trust_store)

			if err != nil {
				return nil, errors.New("error loading trust material: " + err.Error())
			}

			trusted_authorities = x509.NewCertPool()
			_ = trusted_authorities.AppendCertsFromPEM(root_cert)
		}

		if key != "" && certificate != "" {

			clientCert, err := tls.LoadX509KeyPair(certificate, key)

			if err != nil {
				return nil, errors.New("error loading key material: " + err.Error())
			}

			client_certificates = []tls.Certificate{clientCert}
		}

		tlsConfig := tls.Config{
			Certificates: client_certificates,
			RootCAs:      trusted_authorities,
		}

		transport := http.Transport{
			TLSClientConfig: &tlsConfig,
		}

		__client = &http.Client{
			Transport: &transport,
			Timeout:   time.Second * 40,
		}
	}

	return __client, nil
}

func main() {
	home_dir, errh := os.UserHomeDir()
	if errh != nil {
		fmt.Println(errh.Error())
		os.Exit(1)
	}

	identity_dir = home_dir + "/.identityplus"

	var device_name = ""
	device_name, err := os.Hostname()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for i := 1; i < len(os.Args); i++ {

		if os.Args[i] == "-v" {
			verbose = true
		} else if os.Args[i] == "-h" {

			fmt.Println("\nIdentity Plus Command Line Interface")
			fmt.Println("Version: 1.0")
			fmt.Println("Copyright: Identity Plus (https://identity.plus)")
			fmt.Println("License: To be used with the Identity Plus service/platform. Do not distribute.")
			fmt.Println("\n---------\n")
			fmt.Println("Usage: identityplus [flags] command arguments")
			fmt.Println("\n\n-- flags --\n")
			fmt.Println("-h prints this message")
			fmt.Println("-v verbose")
			fmt.Println("-f identity/directory [HOMEDIR/.identityplus]: specify the directory where the identity material will be stored")
			fmt.Println("-d device-name [HOST NAME]: specify the device name to be used for this device")
			fmt.Println("-s api-service [identity.plus]: specify an alternative path for Identity Plus API service")
			fmt.Println("-t trusted-CAs [SYSTEM TRUST STORE]: specify Certificate Authority to trust. It will default to the authorities trusted by the OS")
			fmt.Println("\n\n-- commands --\n")
			fmt.Println("enroll AUTHORIZATION-TOKEN:\nEnroll current device as one of your end user devices. Requires an authorization token that can be obtained from https://my.identity.plus. If the authorization token is issued as part of a service agent in https://platform.identity.plus/organization/xyz.../service/qpr.../agents the identity will be issued as a service agent. You must have the correct role in the service to issue service agent identities.\n")
			fmt.Println("renew:\nRenewes the current identity (user device or service agent)\n")
			fmt.Println("update:\nRenewes the current identity (user device or service agent) if approaching expiration (3/4 of lifetime)\n")
			fmt.Println("issue-service-identity:\nGenerates a server certificate for your service, signed by the Idnetity Plus CA. The call must be made with a valid agent enrolled by the service. To work with Identity Plus issued server certificates we recommend explicitly trusting the Identity Plus Root CA\n")
			fmt.Println("update-service:\nrenewes the server certificate for the service if necessary (reached 3/4 of its lifetime or the domain name has changed). The call must be made with a valid agent employed by the service.\n")
			fmt.Println("list-agents:\nLists all devices you own)\n")
			fmt.Println("\n---\n\n")

			return

		} else if os.Args[i] == "-d" {

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] -d device_name")
			} else {
				device_name = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "-f" {

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] -f directory/to/store/identity")
			} else {
				identity_dir = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "-t" {

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] -t path/to/trusted-root.cer")
			} else {
				trust_store = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "-s" {

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] -s identity.plus.service.domain")
			} else {
				service = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "enroll-user-device" {
			command = os.Args[i]

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] enroll-user-device auto-provisioning-token")
			} else {
				authorization = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "enroll-service-device" {
			command = os.Args[i]

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] enroll-service-device auto-provisioning-token")
			} else {
				authorization = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "enroll" {
			command = os.Args[i]

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] enroll auto-provisioning-token")
			} else {
				authorization = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "assist-enroll" {
			command = os.Args[i]

			if len(os.Args) <= i+1 {
				fmt.Println("Usage: identityplus [ flags ] assist-enroll service")
			} else {
				managed_service = os.Args[i+1]
				i = i + 1
			}

		} else if os.Args[i] == "renew" {
			command = os.Args[i]

		} else if os.Args[i] == "issue-service-identity" {
			command = os.Args[i]

		} else if os.Args[i] == "update" {
			command = os.Args[i]

		} else if os.Args[i] == "update-service" {
			command = os.Args[i]

		} else if os.Args[i] == "list-devices" {
			command = os.Args[i]

		} else {
			url = os.Args[i]
		}
	}

	if verbose {
		fmt.Println("Identity directory: -f " + identity_dir)
		fmt.Println("Device name: -d \"" + device_name + "\"")
		fmt.Println("Identity Plus service: -s \"" + service + "\"")

		if trust_store == "" {
			fmt.Println("Trusted CAs: System Deafult")
		} else {
			fmt.Println("Trusted CAs: " + trust_store)
		}
		fmt.Println("Operation: " + command)
		fmt.Println("")
	}

	// configure logging
	LOG_FILE := identity_dir + "/activity.log"
	logFile, err := os.OpenFile(LOG_FILE, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Panic(err)
	}
	defer logFile.Close()

	// Set log out to file
	// log.SetOutput(logFile)

	// ensure identity directory exists and it is writable
	os.Mkdir(identity_dir, 0700)
	_, err = os.OpenFile(identity_dir+"/test.tmp", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error: directory " + identity_dir + " does not exist or it is not writable")
	} else {
		os.Remove(identity_dir + "/test.tmp")
	}

	if command == "enroll-user-device" {
		var ans = ""

		if authorization == "" {
			ans = interactive_enroll_user_agent(device_name, identity_dir)
		} else {
			ans = enroll_unified(authorization, device_name, identity_dir)
		}

		fmt.Print(ans)
		log.Println(ans)
	}

	if command == "enroll" {
		var ans = ""

		if authorization == "" {
			ans = interactive_enroll_user_agent(device_name, identity_dir)
		} else {
			ans = enroll_unified(authorization, device_name, identity_dir)
		}

		fmt.Print(ans)
		log.Println(ans)
	}

	if command == "assist-enroll" {
		ans := assist_enroll(managed_service, device_name, identity_dir)
		fmt.Print(ans)
		log.Println("Assisting " + managed_service + " with autoprovisioning...")
	}

	if command == "enroll-service-device" {
		ans := enroll_unified(authorization, device_name, identity_dir)
		fmt.Print(ans)
		log.Println(ans)
	}

	if command == "renew" {
		ans := renew(device_name, identity_dir, false)
		fmt.Print(ans)
		log.Println(ans)
	}

	if command == "issue-service-identity" {
		ans := issue_service_identity(device_name, identity_dir, true)
		fmt.Print(ans)
		log.Println(ans)
	}

	if command == "update" {
		ans := renew(device_name, identity_dir, true)
		fmt.Print(ans)
		log.Println(ans)
	}

	if command == "update-service" {
		os.Mkdir(identity_dir+"/service", 0700)
		ans := issue_service_identity(device_name, identity_dir, false)
		fmt.Print(ans)
		log.Println(ans)
	}

	if command == "list-devices" {
		ans := list_devices(device_name, identity_dir)
		fmt.Print(ans)
		log.Println(ans)
	}

	if command == "get url" {
		ans := call(url, device_name, identity_dir)
		fmt.Print(ans)
		log.Println(ans)
	}
}
