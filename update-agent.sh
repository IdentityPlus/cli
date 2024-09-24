#!/bin/bash

if !(crontab -l | grep -q update-agent.sh) ; then
    DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
    echo "installing agent mTLS ID update cron job for 2AM every day"
    (crontab -l ; echo "0 4 * * * $DIR/update-agent.sh \"$1\" \"$2\"") | sort - | uniq - | crontab -
fi

echo -n "updating agent mTLS ID on device... "
RESULT_A=$( /opt/identity.plus/cli/identityplus -f "$1" -d "$2" update )
echo $RESULT_A
