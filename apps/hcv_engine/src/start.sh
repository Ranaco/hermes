#!/bin/sh
vault server -config=/etc/config.hcl &
sleep 5
./setup
wait
