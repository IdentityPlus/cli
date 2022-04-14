#!/bin/bash

SERVICE_NAME="my.service"

# This section is only needed if the computer also runs a service
# and the service is using Identity Plus issued service certificate
# the command will renew the service's TLS Server Certificate
echo -n "updating agent identity ... "
RESULT_A=$( /opt/identityplus/identityplus -f /etc/$SERVICE_NAME/agent-id -d Default update-service )
echo $RESULT_A

# This will renew the TLS Client Certificate in the sepcified directory.
# Regardless if the identity represents a service agent or a user agent bot the command is the same
echo -n "updating service identity ... "
RESULT_S=$( /opt/identityplus/identityplus -f /etc/$SERVICE_NAME/agent-id -d Default update )
echo $RESULT_S

# Adjust acordingly if you removed the server section
if [[ $RESULT_A == "renewed"  ||  $RESULT_S == "renewed" ]]
    then
	echo "reloading nginx service ... "
        service nginx reload
	echo "done."
    else
	echo "nothing to do."
    fi
