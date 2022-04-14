# Identity Plus - Command Line Interface

## Running & Building

## User Manual

./identityplus [flags] command arguments

### Flags
**-h** prints the help message
**-v** enables verbose mode
**-f identity/directory [HOMEDIR/.identityplus]**: specify the directory where the identity material will be stored  
**-d device-name [\"Default Go Test\"]**: specify the device name to be used for this device  
**-s api-service [identity.plus]**: specify an alternative path for Identity Plus API service  
**-t trusted-CAs [SYSTEM TRUST STORE]**: specify Certificate Authority to trust. It will default to the authorities trusted by the OS  

### Operations
enroll AUTHORIZATION-TOKEN
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


