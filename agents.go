package main

// to convert .12 files to .cer + .key file combination
// $ openssl pkcs12 -in client-id.p12 -clcerts -nokeys -out client-id.cer
// $ openssl pkcs12 -in client-id.p12 -clcerts -nodes -nocerts | openssl rsa > client-id.key

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	// "strings"

	//    "crypto/x509"
	"io/ioutil"
	//    "io"
	//	"strconv"
)

func enroll_user_agent(authorization string, device_name string, identity_dir string) string {
	err, ans := do_post("https://sso."+service+"/api/v1", "{\"operation\": \"qrc_unlock\", \"args\": {\"code\": \""+authorization+"\"}}", "", "")

	if err != "" {
		return "Login failed: " + err
	}

	if verbose {
		fmt.Printf(string(ans))
	}

	var response Auth_Response
	json.Unmarshal(ans, &response)

	if response.Error != "" {
		return "Login failed: " + response.Error
	}

	if response.Result.Outcome != "logged in" {
		return "Login failed: " + response.Result.Outcome
	}

	err, ans = do_post("https://sso."+service+"/api/v1", "{\"operation\": \"issue_certificate\", \"args\": {\"token\": \""+response.Result.Token+"\", \"device\": \""+device_name+"\", \"protect\":true}}", "", "")

	if err != "" {
		return "Faild issuing certificate: " + err
	}

	var agent_identity X509_Identity_Response
	json.Unmarshal(ans, &agent_identity)

	if agent_identity.Error != "" {
		return "Failed issuing certificate: " + agent_identity.Error
	}

	p12_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.P12)
	if derr != nil {
		return "Faild decoding certificate: " + err
	}

	ioutil.WriteFile(identity_dir+"/"+device_name+".p12", p12_cert, 0644)
	ioutil.WriteFile(identity_dir+"/"+device_name+".password", []byte(agent_identity.Result.Password), 0644)

	pem_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.Certificate)
	if derr != nil {
		return "Faild decoding certificate: " + err
	}

	ioutil.WriteFile(identity_dir+"/"+device_name+".cer", pem_cert, 0644)

	pem_key, derr := base64.StdEncoding.DecodeString(agent_identity.Result.PrivateKey)
	if derr != nil {
		return "Faild decoding certificate: " + err
	}

	ioutil.WriteFile(identity_dir+"/"+device_name+".key", pem_key, 0644)

	return "success"
}

func employ_service_agent(authorization string, device_name string, identity_dir string) string {
	err, ans := do_post("https://sso."+service+"/api/v1", "{\"operation\": \"issue_service_agent_identity\", \"args\": {\"authorization\": \""+authorization+"\", \"agent-name\": \""+device_name+"\", \"protect\":true}}", "", "")

	if err != "" {
		return "Faild issuing certificate: " + err
	}

	var agent_identity X509_Identity_Response
	json.Unmarshal(ans, &agent_identity)

	fmt.Printf(string(ans))

	if agent_identity.Error != "" {
		return "Failed issuing certificate: " + agent_identity.Error
	}

	p12_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.P12)
	if derr != nil {
		return "Faild decoding certificate: " + err
	}

	ioutil.WriteFile(identity_dir+"/"+device_name+".p12", p12_cert, 0644)
	ioutil.WriteFile(identity_dir+"/"+device_name+".password", []byte(agent_identity.Result.Password), 0644)

	pem_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.Certificate)
	if derr != nil {
		return "Faild decoding certificate: " + err
	}

	ioutil.WriteFile(identity_dir+"/"+device_name+".cer", pem_cert, 0644)

	pem_key, derr := base64.StdEncoding.DecodeString(agent_identity.Result.PrivateKey)
	if derr != nil {
		return "Faild decoding certificate: " + err
	}

	ioutil.WriteFile(identity_dir+"/"+device_name+".key", pem_key, 0644)

	return "success"
}

func renew(device_name string, identity_dir string, force bool) string {
	err, ans := do_post("https://sso."+service+"/api/v1", "{\"operation\": \"renew_certificate\", \"args\": {\"device\": \""+device_name+"\", \"protect\":true, \"force-renew\":"+strconv.FormatBool(force)+"}}", identity_dir+"/"+device_name+".cer", identity_dir+"/"+device_name+".key")

	if err != "" {
		return "Faild issuing certificate: " + err
	}

	var agent_identity X509_Identity_Response
	json.Unmarshal(ans, &agent_identity)

	if agent_identity.Error != "" {
		return "Failed issuing certificate: " + agent_identity.Error
	}

	if agent_identity.Result.Outcome == "renewed" {

		p12_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.P12)
		if derr != nil {
			return "Faild decoding certificate: " + err
		}

		ioutil.WriteFile(identity_dir+"/"+device_name+".p12", p12_cert, 0644)
		ioutil.WriteFile(identity_dir+"/"+device_name+".password", []byte(agent_identity.Result.Password), 0644)

		pem_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.Certificate)
		if derr != nil {
			return "Faild decoding certificate: " + err
		}

		ioutil.WriteFile(identity_dir+"/"+device_name+".cer", pem_cert, 0644)

		pem_key, derr := base64.StdEncoding.DecodeString(agent_identity.Result.PrivateKey)
		if derr != nil {
			return "Faild decoding certificate: " + err
		}

		ioutil.WriteFile(identity_dir+"/"+device_name+".key", pem_key, 0644)
	}

	return agent_identity.Result.Outcome
}

func issue_service_identity(device_name string, identity_dir string, force bool) string {
	err, ans := do_post("https://sso."+service+"/api/v1", "{\"operation\": \"issue_service_certificate\", \"args\": {\"force-renew\":"+strconv.FormatBool(force)+"}}", identity_dir+"/"+device_name+".cer", identity_dir+"/"+device_name+".key")

	if err != "" {
		return "Faild issuing certificate: " + err
	}

	var service_identity X509_Identity_Response
	json.Unmarshal(ans, &service_identity)

	if service_identity.Error != "" {
		return "Failed issuing certificate: " + service_identity.Error
	}

	if service_identity.Result.Outcome == "renewed" {

		p12_cert, derr := base64.StdEncoding.DecodeString(service_identity.Result.P12)
		if derr != nil {
			return "Faild decoding certificate: " + err
		}

		ioutil.WriteFile(identity_dir+"/service/"+service_identity.Result.Name+".p12", p12_cert, 0644)
		ioutil.WriteFile(identity_dir+"/service/"+service_identity.Result.Name+".password", []byte(service_identity.Result.Password), 0644)

		pem_cert, derr := base64.StdEncoding.DecodeString(service_identity.Result.Certificate)
		if derr != nil {
			return "Faild decoding certificate: " + err
		}

		ioutil.WriteFile(identity_dir+"/service/"+service_identity.Result.Name+".cer", pem_cert, 0644)

		pem_key, derr := base64.StdEncoding.DecodeString(service_identity.Result.PrivateKey)
		if derr != nil {
			return "Faild decoding certificate: " + err
		}

		ioutil.WriteFile(identity_dir+"/service/"+service_identity.Result.Name+".key", pem_key, 0644)
	}

	return service_identity.Result.Outcome
}

func list_devices(device_name string, identity_dir string) string {
	err, ans := do_post("https://sso."+service+"/api/v1", "{\"operation\": \"get_active_identities\", \"args\": {}}", identity_dir+"/"+device_name+".cer", identity_dir+"/"+device_name+".key")

	if err != "" {
		return "Faild issuing certificate: " + err
	}

	// var agent_identity X509_Identity_Response
	// json.Unmarshal(ans, &agent_identity)

	return string(ans)
}

func call(url string, device_name string, identity_dir string) string {
	err, ans := do_get(url, "", identity_dir+"/"+device_name+".cer", identity_dir+"/"+device_name+".key")

	if err != "" {
		return "Error Geting URL: " + err
	}

	return string(ans)
}

// func service_identity_renewal(must_renew bool) IDP_Response {
// 	ans := do_put("https://api.identity.plus/v1", "{\"Service-Identity-Request\":{\"force-renewal\": "+strconv.FormatBool(must_renew)+"}}")
// 	return ans

// }

//
// Type mapping definitions for ReST communiation
// We are going to create a big structure to aid automatic identification of types
//

type Simple_Response struct {
	Outcome string `json:"outcome"`
}

type Intent_Reference struct {
	Value   string `json:"value"`
	Outcome string `json:"outcome"`
}

type X509_Identity struct {
	Name        string `json:"name"`
	P12         string `json:"p12"`
	Password    string `json:"password"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private-key"`
	Outcome     string `json:"outcome"`
}

type SSO_Result struct {
	Token   string `json:"token"`
	Outcome string `json:"outcome"`
}

type Auth_Response struct {
	Error  string     `json:"error"`
	Result SSO_Result `json:"result"`
}

type X509_Identity_Response struct {
	Error  string        `json:"error"`
	Result X509_Identity `json:"result"`
}
