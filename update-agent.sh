#!/bin/bash

if !(crontab -l | grep -q update-agent.sh) ; then
    DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
    echo "installing agent update cron job for 2AM every daily"
    (crontab -l ; echo "0 2 * * * $DIR/update-agent.sh $1 $2") | sort - | uniq - | crontab -
fi

echo -n "updating agent identity ... "
RESULT_A=$( /opt/identityplus/identityplus -f /etc/$1/agent-id -d $2 update )
echo $RESULT_A