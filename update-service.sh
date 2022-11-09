#!/bin/bash

echo -n "updating service identity ... "
RESULT_S=$( /opt/identityplus/identityplus -f /etc/$1/agent-id -d $2 update-service )
echo $RESULT_S

if [[ $RESULT_S == "renewed" ]]
    then
	echo "reloading nginx service ... "
        service nginx reload
	echo "done."
    else
	echo "nothing to do ..."
    fi
