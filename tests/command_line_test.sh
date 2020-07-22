#!/bin/bash
bash command_line_cleanup.sh

echo ==================================================
echo Roundtrip encryption/decrryption test using fixed keypair
echo ...
echo +++ `date`: Creating array_counting.txt
max_val=`../bin/encrypt_array |grep delimited | sed 's/.*0,//' | tr -d ']'`
for (( i = 0; i < 1000; i++ )); do
  echo $(((i % $((max_val + 1))))) >> array_counting.txt
done

echo +++ `date`: Creating private and private keys
echo +++ `date`: command_test.priv / command_test.pub
../bin/keygen command_test.priv command_test.pub
echo +++ `date`: Encrypting array_counting.bin
../bin/encrypt_array command_test.pub array_counting.txt array_counting.bin
echo +++ `date`: Decrypting array_counting.bin to array_counting_decrypted.txt
../bin/decrypt_array command_test.priv array_counting.bin array_counting_decrypted.txt

cmp -s array_counting.txt array_counting_decrypted.txt
if [[ $? -eq 0 ]]; then
  echo +++ `date`: array_counting roundtrip successful
else
  echo +++ `date`: array_counting roundtrip failed
fi

echo
echo ==================================================
echo Test of combining encrypted files in ciphertext-space
echo ...
echo +++ `date`: Creating array_12.txt and array_21.txt

for (( i = 0; i < 500; i++ )); do
  echo 1 >> array_12.txt
  echo 2 >> array_21.txt
done
for (( i = 0; i < 500; i++ )); do
  echo 2 >> array_12.txt
  echo 1 >> array_21.txt
done

echo +++ `date`: Encrypting both arrays
../bin/encrypt_array command_test.pub array_12.txt array_12.bin
../bin/encrypt_array command_test.pub array_21.txt array_21.bin
echo +++ `date`: Combining array_12.bin and array_21.bin into array_22.bin
../bin/combine-arrays array_22.bin array_12.bin array_21.bin
echo +++ `date`: Decrypting array_22.bin - max of array_12, array_21
../bin/decrypt_array command_test.priv array_22.bin array_22_decrypted.txt

for (( i = 0; i<1000; i++ )); do
  echo 2 >> array_22.txt
done

cmp -s array_22.txt array_22_decrypted.txt
if [[ $? -eq 0 ]]; then
  echo +++ `date`: array_22 roundtrip successful
else
  echo +++ `date`: array_22 roundtrip failed
fi

echo 
echo ==================================================
echo Test of distributed decryption
echo +++ `date`: creating multiple node public/private pairs
for (( i = 0; i < 10; i++ )); do
  ../bin/keygen node$i.priv node$i.pub
done
echo +++ `date`: combining public keys into single public key
../bin/combine-keys node-combined.pub node[0-9].pub

echo +++ `date`: Encrypting array_counting.txt
../bin/encrypt_array node-combined.pub array_counting.txt array_counting_distributed.bin

echo +++ `date`: Getting shared secrets from each node
for (( i = 0; i < 10; i++ )); do
  ../bin/get_partial_decryption node$i.priv array_counting_distributed.bin array_counting_distributed.ss$i
done

echo +++ `date`: Combining shared secrets
../bin/combine-secrets array_counting_distributed.ss_combined array_counting_distributed.ss[0-9]

echo +++ `date`: Decrypting using shared secrets
../bin/decrypt_partial array_counting_distributed.ss_combined array_counting_distributed.bin array_counting_distributed.txt

cmp -s array_counting.txt array_counting_distributed.txt
if [[ $? -eq 0 ]]; then
  echo +++ `date`: array_counting_distributed roundtrip successful
else
  echo +++ `date`: array_counting_distributed roundtrip failed
fi


