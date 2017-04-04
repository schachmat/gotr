/* This file is part of libgotr.
 * (C) 2016 Markus Teich
 *
 * libgotr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * libgotr is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libgotr; see the file LICENSE.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <errno.h>
#include <pthread.h>
#include <string.h>

// do we need to enumerate all trustdb entries? for displaying them in the
// plugin GUI?
//
// need his_id as index to check for existing trust entries
//
// needed api calls:
// gotr_trust insert_or_get_trust_lvl(his_pkey, his_id, def_lvl)
// set_trust_lvl(his_pkey, his_id, lvl)
// get_rows(his_id)

typedef enum {
	GOTR_TRUST_NONE,
	GOTR_TRUST_TOFU,
	GOTR_TRUST_PKEY
} gotr_trust;

struct gotr_trustdb {
// TODO: need it?
//	pthread_mutex_t lock;
	struct trustdb_node *root;
};

struct trustdb_node {
	struct trustdb_node *left;
	struct trustdb_node *right;
	struct gotr_point his_pkey;
	char *his_id;
	gotr_trust trust;
	// printf "%02x"
};

static struct trustdb_node *create_node(struct trustdb_node *left,
										struct trustdb_node *right,
										struct gotr_point his_pkey,
										const char *his_id,
										gotr_trust trust)
{
	struct trustdb_node *ret = NULL;

	if (!(ret = malloc(sizeof(struct trustdb_node))))
		return NULL;

	ret->left = left;
	ret->right = right;
	ret->his_pkey = his_pkey;
	ret->his_id = strdup(his_id);
	ret->trust = trust;
	return ret;
}

static int node_cmp(const struct trustdb_node *a, const struct trustdb_node *b)
{
	int cmp;

	cmp = memcmp(&a->his_pkey, &b->his_pkey, sizeof(struct gotr_point));
	if (cmp < 0)
		return -1;
	if (cmp > 0)
		return 1;

	cmp = strcmp(a->his_id, b->his_id);
	if (cmp < 0)
		return -1;
	if (cmp > 0)
		return 1;

	return 0;
}

static int parse_hex_digit(unsigned char *dst, const char c)
{
	if (!dst)
		return 0;

	if (c >= '0' && c <= '9') {
		*dst = (*dst & 0xf0) | (c - '0');
		return 1;
	}
	if (c >= 'a' && c <= 'f') {
		*dst = (*dst & 0xf0) | (c - 'a' + 10);
		return 1;
	}
	if (c >= 'A' && c <= 'F') {
		*dst = (*dst & 0xf0) | (c - 'A' + 10);
		return 1;
	}
	return 0;
}

static const char *point_from_string(struct gotr_point *dst, const char *str)
{
	size_t i;
	unsigned char val;
	const char *ptr;

	if (!dst || !str)
		return NULL;

	ptr = str;

	for (i = 0; i < SERIALIZED_POINT_LEN; i++) {
		while (ptr && *ptr && !parse_hex_digit(&val, *ptr))
			ptr++;
		if (!ptr || !*ptr)
			return NULL;
		val <<= 4;

		while (ptr && *ptr && !parse_hex_digit(&val, *ptr))
			ptr++;
		if (!ptr || !*ptr)
			return NULL;

		dst->data[i] = val;
	}
	return ptr++;
}

static gotr_trust parse_trust(const char *str)
{
	if (!strcmp(str, "tofu"))
		return GOTR_TRUST_TOFU;
	if (!strcmp(str, "pkey"))
		return GOTR_TRUST_PKEY;
	return GOTR_TRUST_NONE;
}

static struct trustdb_node* tree_from_list(struct trustdb_node* first, struct trustdb_node* last)
{
	// stop recursion
	if(!first || !last) return NULL;

	struct trustdb_node* root = last;
	struct trustdb_node* tmp = first;

	// first find our root
	while(root != tmp && root->left != tmp) {
		root = root->left;
		tmp  = tmp->right;
	}

	// now detach left and right list
	if(root->left)
		root->left->right = NULL;
	if(root->right)
		root->right->left = NULL;

	// recurse
	root->left = tree_from_list(first, root->left);
	root->right = tree_from_list(root->right, last);
	return root;
}

// merges two lists into one for natural mergesort
static struct trustdb_node* natural_merge(struct trustdb_node* Afirst, struct trustdb_node* Bfirst)
{
	int order;
	struct trustdb_node *cursrc, *curdst, *dst, *lastcurdst;

	if (!Afirst || !Bfirst)
		return (Afirst ? Afirst : Bfirst);

	order = node_cmp(Afirst, Bfirst);
	if (order == 0) {
		gotr_eprintf("duplicate element in trustdb found, merging and minimizing trust level");
		// TODO
	}
	dst = (order < 0 ? Afirst : Bfirst);
	cursrc = (order < 0 ? Bfirst : Afirst);
	curdst = dst->right;
	lastcurdst = dst;

	while (curdst && cursrc) {
		if ((order = node_cmp(curdst, cursrc)) < 0) {
			lastcurdst = curdst;
			curdst = curdst->right;
		} else if (order > 0) {
			curdst->left->right = cursrc;
			cursrc->left = curdst->left;
			curdst->left = cursrc;
			cursrc = cursrc->right;
			curdst->left->right = curdst;
		} else {
			gotr_eprintf("duplicate element in trustdb found, merging and minimizing trust level");
			// TODO
		}
	}
	if (cursrc) {
		lastcurdst->right = cursrc;
		cursrc->left = lastcurdst;
	}

	return dst;
}

// uses natural mergesort to sort the list
static struct trustdb_node* natural_mergesort(struct trustdb_node* first)
{
	int order;
	struct trustdb_node *tmp = first->right;
	struct trustdb_node *last = first;

	if (!first)
		return NULL;

	while (tmp) {
		if ((order = node_cmp(last, tmp)) < 0) {
			last = tmp;
			tmp = tmp->right;
		} else if (order > 0) {
			break;
		} else {
			gotr_eprintf("duplicate element in trustdb found, merging and minimizing trust level");
			// TODO
		}
	}

	if (tmp) {
		tmp->left = NULL;
		last->right = NULL;
		return natural_merge(first, natural_mergesort(tmp));
	} else {
		// whole list already sorted
		return first;
	}
}

// returns the node if found, else the parent node
static struct trustdb_node* find_node(struct gotr_trustdb *db, struct gotr_point his_pkey, const char *his_id)
{
//	struct trustdb_node *ret, *;

//	while
}

// TODO: handle failure: (!db )
gotr_trust get_or_insert(struct gotr_trustdb *db, struct gotr_point his_pkey, const char *his_id)
{

}

struct gotr_trustdb *gotr_read_trustdb(const char *filename)
{
	FILE *fp;
	char line[4096];
	char *tab;
	const char *ptr, *his_id;
	struct trustdb_node *cur, *first = NULL, *last = NULL;
	struct gotr_trustdb *ret = NULL;
	struct gotr_point his_pkey;

	if (!filename || !(ret = malloc(sizeof(struct gotr_trustdb))))
		return NULL;

	// TODO: store filename in ret for write() function?
//	if ((errno = pthread_mutex_init(&ret->lock, NULL))) {
//		gotr_eprintf("failed to init trustdb mutex for file %s:", filename);
//		return NULL;
//	}

	if (!(fp = fopen(filename, "r"))) {
		gotr_eprintf("could not open trustdb file %s for reading, using empty trustdb. The error was:", filename);
		ret->root = NULL;
		return ret;
	}

	while (fgets(line, sizeof(line), fp)) {
		// read his_pkey
		if (!(ptr = point_from_string(&his_pkey, line))) {
			gotr_eprintf("invalid trustdb entry encountered, ignoring...");
			continue;
		}

		tab = strchr(ptr, '\t');
		if (!tab) {
			gotr_eprintf("invalid trustdb entry encountered, ignoring...");
			continue;
		}
		his_id = tab++;

		tab = strchr(his_id, '\t');
		if (!tab) {
			gotr_eprintf("invalid trustdb entry encountered, ignoring...");
			continue;
		}
		*tab = '\0';

		cur = create_node(last, NULL, his_pkey, strdup(his_id), parse_trust(tab++));
		if (!first)
			first = cur;
		if (last)
			last->right = cur;
		last = cur;
	}

	// sort
	first = natural_mergesort(first);

	// find new last element in sorted list
	last = first;
	while (last && last->right)
		last = last->right;

	// build tree
	ret->root = tree_from_list(first, last);

	fclose(fp);
	return ret;
}
