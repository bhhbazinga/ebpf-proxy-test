#! /usr/bin/bash
rm -f *.txt
rm -f *.normal_txt
rm -f tmp.txt

list="100 1000 5000 10000"

for bytes in $list; do
    rm -f tmp.txt
    ./benchmark 127.0.0.1:2000 127.0.0.1:3000 $bytes 10200 > tmp.txt
    cat tmp.txt | sort -n | sed -n '100,10100 p' > ebpf_$bytes
done
