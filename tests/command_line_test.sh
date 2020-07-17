#!/bin/bash

max_val=`../bin/encrypt_array |grep delimited | sed 's/.*0,//' | tr -d ']'`
rm -f array*.txt
for (( i = 0; i < 1000; i++ )); do
  echo $(((i % $((max_val + 1))))) >> array_counting.txt
done

date
../bin/keygen command_test.priv command_test.pub
date
../bin/encrypt_array command_test.pub array_counting.txt array_counting.bin
date
../bin/decrypt_array command_test.priv array_counting.bin array_counting_decrypted.txt
date

cmp -s array_counting.txt array_counting_decrypted.txt
if [[ $? -eq 0 ]]; then
  echo counting roundtrip successful
else
  echo counting roundtrip failed
fi


for (( i = 0; i < 500; i++ )); do
  echo 1 >> array_12.txt
  echo 2 >> array_21.txt
done
for (( i = 0; i < 500; i++ )); do
  echo 2 >> array_12.txt
  echo 1 >> array_21.txt
done

date
../bin/encrypt_array command_test.pub array_12.txt array_12.bin
date
../bin/encrypt_array command_test.pub array_21.txt array_21.bin
date
../bin/combine-arrays array_22.bin array_12.bin array_21.bin
date
../bin/decrypt_array command_test.priv array_22.bin array_22_decrypted.txt

for (( i = 0; i<1000; i++ )); do
  echo 2 >> array_22.txt
done

cmp -s array_22.txt array_22_decrypted.txt
if [[ $? -eq 0 ]]; then
  echo counting roundtrip successful
else
  echo counting roundtrip failed
fi
