#!/bin/bash

echo -n "updating agent identity ... "
RESULT_A=$( /opt/identityplus/identityplus -v -f /etc/$1/agent-id -d $2 update )
echo $RESULT_A