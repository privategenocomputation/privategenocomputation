#ifndef GEN_READER_H
#define GEN_READER_H

#include <fstream>
#include <iterator>
#include <vector>
#include <iostream>
#include <string>

//File paths to read
#define GPATH "../data/gen.dat"
#define PPATH "../data/phe.dat"
#define APATH "../data/anc.dat"
#define NPATH "../data/names_table.txt"
#define IPATH "../data/ids_table.txt"
//File path to recored
#define RPATH "../data/network.csv "
//Set to 1 if in record mod, o/w set to 0
unsigned int RECORD_MOD(0);

using namespace std;

// to recored
//headder: gen;phe;anc;part;poly;Load;Parm;KeyGen;GenObj;EncGen;EncPhe;EncAnc;EncTot;LC;C_MU;C_SPU;Combine;Decode;DecTot;DecTotApprox
ofstream rec(RPATH, ios::app);

// return genotype
vector<char> readGen(){
	ifstream gen_data(GPATH, ios::binary);
	vector<char> gen((istreambuf_iterator<char>(gen_data)), (istreambuf_iterator<char>()));
	gen_data.close();
	return gen;
}

// return phenotype
vector<char> readPhe(){
	ifstream phe_data(PPATH, ios::binary);
	vector<char> phe((istreambuf_iterator<char>(phe_data)), (istreambuf_iterator<char>()));
	phe_data.close();
	return phe;
}

// return ancestry
vector<char> readAnc(){
	ifstream anc_data(APATH, ios::binary);
	vector<char> anc((istreambuf_iterator<char>(anc_data)), (istreambuf_iterator<char>()));
	anc_data.close();
	return anc;
}

// return names
vector<string> readNames(){
	ifstream nam_data(NPATH);
	vector<string> nam;
	string line;
	while (nam_data >> line) nam.push_back(line);
	nam_data.close();
	return nam;
}

// return the ids
vector<string> readIds(){
	ifstream ids_data(IPATH);
	vector<string> ids;
	string line;
	while (ids_data >> line) ids.push_back(line);
	ids_data.close();
	return ids;
}

#endif // GEN_READER_H
