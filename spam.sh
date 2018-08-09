#!/bin/bash
for i in {1..1}
do
   cat dartdone.log | ./demo 127.0.0.1 1048576 1 1
done
