#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct enc_node {
	char val;
	struct enc_node * next;
} enc_node_t;

typedef struct node {
	char val[8];
	struct node * next;
} node_t;

typedef struct node_s {
	enc_node_t* val;
	struct node_s * next;
} node_s_t;

node_t * names;
node_s_t * ids;

enc_node_t * data_gen;
enc_node_t * data_phe;
enc_node_t * data_anc;

node_t* init_new_node(node_t* list, char* val) {
	node_t* newnode = malloc(sizeof(node_t));
	newnode->next = list;
	int i;
	for (i = 0; i < 8; i++) {
		newnode->val[i] = val[i];
	}
	return newnode;
}

node_s_t* init_new_node_s(node_s_t* list, enc_node_t* val) {
	node_s_t* newnode = malloc(sizeof(node_s_t));
	newnode->next = list;
	newnode->val = val;
	return newnode;
}

enc_node_t* init_new_enc_node(enc_node_t* list, char val) {
	enc_node_t* newnode = malloc(sizeof(enc_node_t));
	newnode->next = list;
	newnode->val = val;
	return newnode;
}

void insert_names(char* val) {
	names = init_new_node(names, val);
}
void insert_ids(enc_node_t* val) {
	ids = init_new_node_s(ids, val);
}

void insert_data_gen(char val) {
	data = init_new_enc_node(data_gen, val);
}

void insert_data_phe(char val) {
	data = init_new_enc_node(data_phe, val);
}

void insert_data_anc(char val) {
	data = init_new_enc_node(data_anc, val);
}

void print_enc_node(enc_node_t* list) {
	int count = 0;
	while (list != NULL) {
		list = list->next;
		count++;
	}
}

enc_node_t* inverse_enc_node(enc_node_t* list, enc_node_t* temp) {
	if (list == NULL) {
		return list;
	}
	if (list->next != NULL) {
		enc_node_t* oldNext = list->next;
		list->next = temp;
		return inverse_enc_node(oldNext, list);
	} else {
		list->next = temp;
		return list;
	}

}

node_t* inverse_node(node_t* list, node_t* temp) {
	if (list == NULL) {
		return list;
	}
	if (list->next != NULL) {
		node_t* oldNext = list->next;
		list->next = temp;
		return inverse_node(oldNext, list);
	} else {
		list->next = temp;
		return list;
	}

}

node_s_t* inverse_node_s(node_s_t* list, node_s_t* temp) {
	if (list == NULL) {
		return list;
	}
	if (list->next != NULL) {
		node_s_t* oldNext = list->next;
		list->next = temp;
		list->val = inverse_enc_node(list->val, NULL);
		return inverse_node_s(oldNext, list);
	} else {
		list->next = temp;
		list->val = inverse_enc_node(list->val, NULL);
		return list;
	}

}

void print_node(node_t* list) {
	node_t* temp = list;
	while (temp != NULL) {
		printf("%s\n", temp->val);
		temp = temp->next;
	}
}

void print_node_s(node_s_t* list) {
	node_s_t* temp = list;
	while (temp != NULL) {
		print_enc_node(temp->val);
		printf("\n");
		temp = temp->next;
	}
}

void read_name(FILE* fp) {
	int readC;
	char name[8];
	int counter = 0;
	while (counter < 9) {
		if ((readC = getc(fp)) == -1) {
			return;
		}
		if (readC == ';') {
			name[7] = '\0';
			insert_names(name);
		} else if (readC == '\n') {
		} else {
			name[counter % 9] = readC;
		}
		counter++;
	}
}

void read_id(FILE* fp) {
	int readC = 0;
	enc_node_t* id = NULL;
	while (readC != ';') {
		if ((readC = getc(fp)) == -1) {
			return;
		}
		if (readC == ';') {
			id = init_new_enc_node(id, '\0');
			insert_ids(id);
			id = NULL;
		} else if (readC == '\n') {
		} else {
			id = init_new_enc_node(id, readC);
		}
	}
}

void read_names() {
	FILE * fp;
	fp = fopen("./names_table.txt", "r");
	if (fp == NULL)
		exit(EXIT_FAILURE);

	while (!feof(fp)) {
		read_name(fp);
	}

	fclose(fp);
	names = inverse_node(names, NULL);
}

void read_ids() {
	FILE * fp;
	fp = fopen("./ids_table.txt", "r");
	if (fp == NULL)
		exit(EXIT_FAILURE);

	while (!feof(fp)) {
		read_id(fp);
	}

	fclose(fp);

	ids = inverse_node_s(ids, NULL);
}

void read_enc_data(char* file, int which) {
	FILE * fp;
	int buff = 0;
	fp = fopen(file, "r");
	if (fp == NULL)
		exit(EXIT_FAILURE);

	while (!feof(fp)) {
		if (fread(&buff, 1, 1, fp) == -1) {
			break;
		}
		if (which == 1) {
			insert_data_gen(buff);
		} else if (which == 2){
			insert_data_phe(buff);
		} else if (which == 3){
			insert_data_anc(buff);
		}
	}

	fclose(fp);
}

void read_data_gen() {
	read_enc_data("./gen.dat", 6);
	data = inverse_enc_node(data, NULL);
}

void read_data_phe() {
	read_enc_data("./phe.dat", 6);
	data = inverse_enc_node(data, NULL);
}

void read_data_anc() {
	read_enc_data("./anc.dat", 6);
	data = inverse_enc_node(data, NULL);
}

int size_of_enc_node(enc_node_t* list) {
	int count = 0;
	enc_node_t* temp = list;
	while (temp != NULL) {
		count++;
		temp = temp->next;
	}
	return count;
}

int size_of_data_gen() {
	return size_of_enc_node(data_gen);
}

int size_of_data_phe() {
	return size_of_enc_node(data_phe);
}

int size_of_data_anc() {
	return size_of_enc_node(data_anc);
}

int size_of_node(node_t* list) {
	int count = 0;
	node_t* temp = list;
	while (temp != NULL) {
		count++;
		temp = temp->next;
	}
	return count;
}

int size_of_names() {
	return size_of_node(names);
}

int size_of_node_s(node_s_t* list) {
	int count = 0;
	node_s_t* temp = list;
	while (temp != NULL) {
		count++;
		temp = temp->next;
	}
	return count;
}

int size_of_ids() {
	return size_of_node_s(ids);
}

int find_name_id(char* name) {
	int res = -1;
	int count = 0;
	node_t* temp = names;
	while (temp != NULL) {
		const char* nameInt = temp->val;
		if (!strcmp(name, nameInt)) {
			res = count;
			break;
		}
		temp = temp->next;
		count++;
	}
	return res;
}

int find_ids_id(char* id) {
	int res = -1;
	int count = 0;
	node_s_t* temp = ids;
	while (temp != NULL) {
		int count2 = 0;
		enc_node_t* temp2 = temp->val;
		while (temp2 != NULL) {
			count2++;
			temp2 = temp2->next;
		}
		char res2[count2 + 1];
		temp2 = temp->val;
		count2 = 0;
		while (temp2 != NULL) {
			res2[count2] = temp2->val;
			count2++;
			temp2 = temp2->next;
		}
		res2[count2] = '\0';
		const char* nameInt = res2;
		if (!strcmp(id, nameInt)) {
			res = count;
			break;
		}
		temp = temp->next;
		count++;
	}
	return res;
}

char get_char_in_enc_node(int n, enc_node_t* list) {
	int count = 0;
	enc_node_t* temp = list;
	while (temp != NULL) {
		if (count == n) {
			return temp->val;
		}
		temp = temp->next;
		count++;
	}
	return '\0';
}

char get_char_in_data_gen(int n) {
	return get_char_in_enc_node(n, data_gen);
}

char get_char_in_data_phe(int n) {
	return get_char_in_enc_node(n, data_phe);
}

char get_char_in_data_anc(int n) {
	return get_char_in_enc_node(n, data_anc);
}

void free_enc_node_t(enc_node_t* list) {
	enc_node_t* temp = list;
	enc_node_t* temp2;
	while(temp!=NULL) {
		temp2 = temp;
		temp = temp->next;
		free(temp2);
	}
}

void free_node_t(node_t* list) {
	node_t* temp = list;
	node_t* temp2;
	while(temp!=NULL) {
		temp2 = temp;
		temp = temp->next;
		free(temp2);
	}
}

void free_node_s_t(node_s_t* list){
	node_s_t* temp = list;
	node_s_t* temp2;
	while(temp!=NULL) {
		temp2 = temp;
		free_enc_node_t(temp->val);
		temp = temp->next;
		free(temp2);
	}
}

void free_data_gen() {
	free_enc_node_t(data_gen);
	ancSkeys = NULL;
}
void free_data_phe() {
	free_enc_node_t(data_phe);
	ancSkeys = NULL;
}
void free_data_anc() {
	free_enc_node_t(data_anc);
	ancSkeys = NULL;
}
