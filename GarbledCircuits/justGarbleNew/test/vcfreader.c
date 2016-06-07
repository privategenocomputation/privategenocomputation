#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct node {
	char* val;
	struct node * next;
} node_t;

typedef struct elem {
	char* name;
	node_t* list;
	struct elem * next;
} map_t;

node_t * names = NULL;
node_t * chrms = NULL;
node_t * poss = NULL;
node_t * ids = NULL;
node_t * refs = NULL;
node_t * alts = NULL;
node_t * gts = NULL;
node_t * ds = NULL;

node_t* init_new_node(node_t * list,char* val) {
	node_t* newnode = malloc(sizeof(node_t));
	newnode->next = list;
	newnode->val = malloc(strlen(val) + 1);
	memcpy(newnode->val, val, strlen(val));
	newnode->val[strlen(val)] = '\0';
	return newnode;
}

void insert_names(char* val) {
	names = init_new_node(names, val);
}
void insert_chrms(char* val) {
	chrms = init_new_node(chrms, val);
}
void insert_poss(char* val) {
	poss = init_new_node(poss, val);
}
void insert_ids(char* val) {
	ids = init_new_node(ids, val);
}
void insert_refs(char* val) {
	refs = init_new_node(refs, val);
}
void insert_alts(char* val) {
	alts = init_new_node(alts, val);
}


void free_list(node_t * list, int print) {
	node_t * temp = list;
	while (temp != NULL) {
		node_t * temp2 = temp;
		if (print)
			printf("%s\n", temp->val);
		temp = temp->next;
		free(temp2->val);
		free(temp2);
	}
}

int main(void) {
	FILE * fp;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;
	int counter = 0;

	fp = fopen("../data200.vcf", "r");
	if (fp == NULL)
		exit(EXIT_FAILURE);

	while ((read = getline(&line, &len, fp)) != -1) {
		counter++;
		if (counter == 30) {
			int counter_internal = 0;
			char *pch;
			pch = strtok(line, "\t\n");
			while (pch != NULL) {
				if (counter_internal >= 6) {
					insert_names(pch);
				}
				pch = strtok(NULL, "\t\n");
				counter_internal++;
			}
		}
		if (counter > 30) {
			int counter_internal = 0;
			char *pch;
			pch = strtok(line, "\t\n");
			while (pch != NULL) {
				if (counter_internal == 0) {
					insert_chrms(pch);
				}
				if (counter_internal == 1) {
					insert_poss(pch);
				}
				if (counter_internal == 2) {
					insert_ids(pch);
				}
				if (counter_internal == 3) {
					insert_refs(pch);
				}
				if (counter_internal == 4) {
					insert_alts(pch);
				}
				if (counter_internal == 5) {

				}
				pch = strtok(NULL, "\t\n");
				counter_internal++;
			}
		}
	}
	free_list(names,0);
	free_list(chrms,0);
	free_list(poss,0);
	free_list(ids,0);
	free_list(refs,0);
	free_list(alts,0);

	fclose(fp);
	if (line)
		free(line);
	exit(EXIT_SUCCESS);
}
