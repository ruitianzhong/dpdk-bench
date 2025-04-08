#include <assert.h>
#include <rte_hash_crc.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "../dpdk_app.h"
#include "../util.h"

struct hash_table* hash_table_create(int nb_buckets) {
  struct hash_table* ht;
  ht = calloc(1, sizeof(struct hash_table));
  assert(ht != NULL);
  ht->buckets = calloc(nb_buckets, sizeof(struct hash_bucket));
  assert(ht->buckets != NULL);
  for (int i = 0; i < nb_buckets; i++) {
    TAILQ_INIT(&ht->buckets[i].head);
  }
  ht->nb_buckets = nb_buckets;
  return ht;
}

void hash_table_free(struct hash_table* ht) {
  assert(ht != NULL);
  free(ht->buckets);
  free(ht);
  return;
}

void hash_table_insert(struct hash_table* ht, struct ipv4_5tuple tuple,
                       void* data) {
  uint32_t key = rte_hash_crc(&tuple, sizeof(struct ipv4_5tuple), 0);
  key = key % ht->nb_buckets;
  struct hash_element* element = NULL;
  TAILQ_FOREACH(element, &ht->buckets[key].head, tailq) {
    if (tuple_equal(&tuple, &element->tuple)) {
      rte_panic("match\n");
    }
  }
  element = calloc(1, sizeof(struct hash_element));
  element->data = data;
  element->tuple = tuple;  // fix bug here
  assert(element != NULL);
  TAILQ_INSERT_TAIL(&ht->buckets[key].head, element, tailq);
  return;
}

void* hash_table_look_up(struct hash_table* ht, struct ipv4_5tuple tuple) {
  uint32_t key = rte_hash_crc(&tuple, sizeof(struct ipv4_5tuple), 0);
  key = key % ht->nb_buckets;
  struct hash_bucket* bucket = &ht->buckets[key];
  struct hash_element* element = NULL;
  void* data = NULL;
  TAILQ_FOREACH(element, &bucket->head, tailq) {
    if (tuple_equal(&element->tuple, &tuple)) {
      data = element->data;
      break;
    }
  }
  return data;
}