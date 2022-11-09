# Identity Plus - Command Line Interface

The Indentity Plus CLI is a simple, command line tool for all identity plus basic functions. While these functions are available as API and can be perfomed from within applications, the CLI can come in handy to automate deployments and maintenance using an automation suite.

### Definitions 

Identity Plus is a device identity suite built upon the TLS communication stack. In this documentation we will assume you are already familiar with the following technologies and concepts:

#### TLS

Transport Layer Security, the successor of SSL, is a communication layer built upon the TCP stack to ensure confientiality of the communication and the identity of one or both the communicating parties. The term is also used denote the simple form of TLS communication, when only one of the parties presents identity information, the minimum necessary for TLS to work.

#### MATLS

Mutually Authenticated TLS, is the full version of TLS, when both parties present identity information

#### X.509 Certificate

Colloquially known as a TLS Certificate or SSL Certificate, the X.509 Certificate is a Criptographic instrument that gives a computer software the ability to prove identity by means of a private key. The public part of the certificate, contains identity information, verifying (public) key and various other information. Structurally all X.509 Certificates are the same, they only difer in their purpose which is documented in the cerificate: authority (certificates that sign other certificates), sever (certificates that prove server identity), client certificates (certificates that prove client identity)

## Running & Building

The Identity Plus command line interface is built in GoLang. We recomment that you build the application for your own specific platform. To do so, please follow the stepts:

**1.** Install the GoLang development platform  
**2.** Check out this project from the repository  
**3.** Open a terminal window and change direcory into the Identity Plus CLI directory you just checked out  
**4.** Build the application:  

        $ go mod init identityplus  
        $ go build
  
**5.** You are done, the "identityplus" file in the current folder is your executable  
**6.** You can also run the identityplus CLI without building it  

        $ go run identityplus.go agents.go ...  


## User Manual

./identityplus [flags] command arguments

### Flags
**-h** prints the help message  
**-v** enables verbose mode  
**-f identity/directory [HOMEDIR/.identityplus]**: specify the directory where the identity material will be stored  
**-d device-name [\"Default Go Test\"]**: specify the device name to be used for this device

### Debug Flags
These flags are only need to be specified in case of debugging, otherwise they should stay default
**-s api-service [identity.plus]**: specify an alternative path for Identity Plus API service  
**-t trusted-CAs [SYSTEM TRUST STORE]**: specify Certificate Authority to trust. It will default to the authorities trusted by the OS  

### Operations

#### enroll AUTHORIZATION-TOKEN
Enroll current device as one of your end user devices. Requires an authorization token that can be obtained from https://signon.identity.plus

#### employ AUTHORIZATION-TOKEN
Employ current device as an agent to one of your services. Requires an authorization token that can be obtained from https://my.identity.plus/ORG/service/SERVICE-ID/agents

#### renew
Renewes the current identity (user device or service agent)

#### update
Renewes the current identity (user device or service agent) if approaching expiration (3/4 of lifetime)

#### issue-service-identity
Generates a server certificate for your service, signed by the Idnetity Plus CA. The call must be made with a valid agent enrolled by the service. To work with Identity Plus issued server certificates we recommend explicitly trusting the Identity Plus Root CA

#### update-service
Renewes the server certificate for the service if necessary (reached 3/4 of its lifetime or the domain name has changed). The called must be made with a valid agent employed by the service.

#### list-devices
Lists all devices you own)

## Make a Linux Cron Job


