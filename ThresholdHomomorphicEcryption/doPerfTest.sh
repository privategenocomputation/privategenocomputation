#! /bin/sh

#parms
header="gen;phe;anc;part;poly;Load;Parm;KeyGen;GenObj;EncGen;EncPhe;EncAnc;EncTot;LC;C_MU;C_SPU;Combine;Decode;DecTot;DecTotApprox;"
gen=7
#make SEAL lib
cd SEAL
make all

#make THELC.exe
cd ../THE/
make all

#create file
touch ../data/eval.csv
echo ${header} > ../data/eval.csv

for poly in 4096
do
	for anc in `seq 0 2`
	do
		for phe in `seq 0 2`
		do
			for nb in `seq 1 191`
			do
				echo "THELC.exe $gen $phe $anc $nb $poly 1 0 0"
				./../bin/THELC.exe $gen $phe $anc $nb $poly 1 0 0
			done
		done
	done
done

