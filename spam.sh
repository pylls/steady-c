#!/bin/bash
for i in {1..1}
do
   cat example-log-data.log | ./demo 127.0.0.1 16 1 1
done
