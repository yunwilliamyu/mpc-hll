#!/bin/bash

rm -f array_list.txt array_list2.txt
for (( i = 0; i < 10000; i++ )); do
  echo $(((i % 64)+1)) >> array_list.txt
done

../bin/keygen command_test.priv command_test.pub
../bin/encrypt_array command_test.pub array_list.txt array.bin
../bin/decrypt_array command_test.priv array.bin array_list2.txt


cmp -s array_list.txt array_list2.txt
if [[ $? -eq 0 ]]; then
  echo counting roundtrip successful
else
  echo counting roundtrip failed
fi
