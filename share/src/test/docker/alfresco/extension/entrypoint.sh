#!/bin/sh

set -e

ip=`hostname -I | awk '{print $1}'`
hostip=`echo "${ip}" | sed -E 's/([0-9]+\.[0-9]+)\.0\.[0-9]+/\1.0.1/'`
hostname="${DOCKER_HOST_NAME}"
echo "${hostip}   ${hostname}" >> /etc/hosts

bash -c "$@"