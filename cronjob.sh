#!/bin/bash

echo -n "updating agent identity ... "
RESULT_A=$( /opt/identityplus/identityplus -f /etc/home.stefan.idplus.zone/agent-id -d Default update-service )
echo $RESULT_A

echo -n "updating service identity ... "
RESULT_S=$( /opt/identityplus/identityplus -f /etc/home.stefan.idplus.zone/agent-id -d Default update )
echo $RESULT_S

if [[ $RESULT_A == "renewed"  ||  $RESULT_S == "renewed" ]]
    then
	echo "reloading nginx service ... "
        service nginx reload
	echo "done."
    else
	echo "nothing to do."
    fi
