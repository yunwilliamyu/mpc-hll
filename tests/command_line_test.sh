#!/bin/bash

rm counting.txt
for (( i = 1; i < 65; i++ )); do
  echo $i >> counting.txt
done

../bin/keygen applesauce.priv applesauce.pub
../bin/encrypt_array applesauce.pub counting.txt out.bin
../bin/decrypt_array applesauce.priv out.bin counting2.txt


cmp -s counting.txt counting2.txt
if [[ $? -eq 0 ]]; then
  echo counting roundtrip successful
else
  echo counting roundtrip failed
fi
