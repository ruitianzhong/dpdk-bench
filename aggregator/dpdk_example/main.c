/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

 #include <stdio.h>
 #include <string.h>
 #include <stdint.h>
 #include <errno.h>
 #include <sys/queue.h>
 
 #include <rte_memory.h>
 #include <rte_launch.h>
 #include <rte_eal.h>
 #include <rte_per_lcore.h>
 #include <rte_lcore.h>
 #include <rte_debug.h>
 #include <rte_lcore_var.h>
 #include <rte_spinlock.h>
 #include <rte_hash.h>
 #include <rte_hash_crc.h>
 #include <rte_ip.h>
 #define DEFAULT_HASH_FUNC       rte_hash_crc
 #define HASH_ENTRIES 2048
 #include <stdlib.h>
 
 
 static RTE_LCORE_VAR_HANDLE(int, per_core_counts);
 
 rte_spinlock_t lock;
 static int counter = 0;
 static alignas(RTE_CACHE_LINE_SIZE) int values[HASH_ENTRIES];
 
 /* Launch a function on lcore. 8< */
 #include <sys/queue.h>
 
 struct test_tailq
 {
     int idx;
     TAILQ_ENTRY(test_tailq) entries;
 };
 
 
 
 static int
 lcore_hello(__rte_unused void *arg)
 {
     unsigned lcore_id;
     lcore_id = rte_lcore_id();
     printf("hello from core %u\n", lcore_id);
     return 0;
 }
 /* >8 End of launching function on lcore. */
 
 
 struct __rte_packed_begin ipv4_5tuple
 {
     uint32_t ip_dst;
     uint32_t ip_src;
     uint16_t port_dst;
     uint16_t port_src;
     uint8_t proto;
 } __rte_packed_end;
 
 struct ipv4_l3fwd_route
 {
     struct ipv4_5tuple key;
     int value;
 };
 
 static struct ipv4_l3fwd_route arr[] = {
     {{RTE_IPV4(1, 1, 1, 1), RTE_IPV4(2, 2, 2, 2), 101, 11, IPPROTO_TCP}, 42},
 };
 
 static int hash_function(){
      // init hash table
      char ht_name[64];
      snprintf(ht_name, sizeof(ht_name), "foo");
      struct rte_hash_parameters param = {
          .name = NULL,
          .entries = HASH_ENTRIES,
          .key_len = sizeof(struct ipv4_5tuple),
          .hash_func = DEFAULT_HASH_FUNC,
          .hash_func_init_val = 0,
      };
      param.name = ht_name;
      // NUMA-aware memory allocation here
      param.socket_id = rte_socket_id();
      struct rte_hash *ht = rte_hash_create(&param);
 
      if (ht == NULL)
      {
          rte_exit(EXIT_FAILURE, "unable to create hash table");
      }
 
      int ret;
 
      ret = rte_hash_add_key(ht, &arr[0].key);
 
      if (ret < 0)
      {
          rte_exit(EXIT_FAILURE, "Unable to add entry");
      }
 
      values[ret] = arr[0].value;
 
      ret = rte_hash_lookup(ht, &arr[0].key);
      if (ret<0){
         rte_exit(EXIT_FAILURE,"Unable to look up entry");
      }
      printf("value is %d\n", values[ret]);
 
      ret = rte_hash_add_key(ht, &arr[0].key);
 
      if (ret < 0)
      {
          rte_exit(EXIT_FAILURE, "add key fail");
      }
      void *data;
      ret = rte_hash_lookup_data(ht, &arr[0].key, &data);
      if (ret < 0)
      {
          rte_exit(EXIT_FAILURE, "look up key failure");
      }
      printf("%d\n", data == NULL);
      int * x = malloc(sizeof(int));
      *x = 99;
 
      ret = rte_hash_add_key_data(ht, &arr[0].key, x);
 
      if (ret<0){
          rte_exit(EXIT_FAILURE, "add key failure");
      }
 
      ret = rte_hash_lookup_data(ht, &arr[0].key, (void **)&x);
      if (ret<0){
          rte_exit(EXIT_FAILURE, "lookup fialure");
      }
      printf("%d\n", *x);
 
      printf("hashtable size:%d\n", rte_hash_count(ht));
      ret = rte_hash_del_key(ht, &arr[0].key);
      if (ret<0){
          rte_exit(EXIT_FAILURE, "del key");
      }
      printf("ht size:%d\n", rte_hash_count(ht));
 
      rte_hash_free(ht);
 }
 
 static int
 lcore_remote_function(void *arg)
 {
     unsigned lcore_id = rte_lcore_id();
     printf("hello world from core %u\n", lcore_id);
 
     int total = 1000000;
     int *x = RTE_LCORE_VAR(per_core_counts);
 
     while (total--)
     {
         (*x)++;
         // rte_delay_us_sleep(1);
     }
     printf("current x:%d\n", *x);
 
     total = 10000;
     while (total--)
     {
         rte_spinlock_lock(&lock);
         counter++;
         rte_spinlock_unlock(&lock);
         rte_delay_us(1);
     }
 
     return 0;
 }
 
 static void init_per_lcore()
 {
     rte_spinlock_init(&lock);
 
     RTE_LCORE_VAR_ALLOC(per_core_counts);
 
     int *cnt;
     unsigned int lcore_id;
     RTE_LCORE_VAR_FOREACH(lcore_id, cnt, per_core_counts)
     {
         *cnt = lcore_id;
         printf("lcore id : %u cnt: %d\n", lcore_id, *cnt);
     }
     printf("the default lcore number is %d\n", RTE_MAX_LCORE);
 }
 
 /* Initialization of Environment Abstraction Layer (EAL). 8< */
 int main(int argc, char **argv)
 {
     int ret;
     unsigned lcore_id;
 
     ret = rte_eal_init(argc, argv);
     if (ret < 0)
         rte_panic("Cannot init EAL\n");
     /* >8 End of initialization of Environment Abstraction Layer */
     init_per_lcore();
 
     /* Launches the function on each lcore. 8< */
     RTE_LCORE_FOREACH_WORKER(lcore_id)
     {
         /* Simpler equivalent. 8< */
         rte_eal_remote_launch(lcore_hello, NULL, lcore_id);
         /* >8 End of simpler equivalent. */
     }
 
     /* call it on main lcore too */
     lcore_hello(NULL);
     /* >8 End of launching the function on each lcore. */
     printf("Waiting here!\n");
     rte_eal_mp_wait_lcore();
     rte_eal_mp_remote_launch(lcore_remote_function, NULL, CALL_MAIN);
     /* clean up the EAL */
     rte_eal_mp_wait_lcore();
     unsigned id;
     int *cnt;
     RTE_LCORE_VAR_FOREACH(id, cnt, per_core_counts)
     {
         if (id == rte_lcore_count())
         {
             break;
         }
         printf("%d on locre %d\n", *cnt, id);
     }
     printf("Total lcore count:%d\n", rte_lcore_count());
     printf("global counter:%d\n", counter);
     hash_function();
     rte_eal_cleanup();
 
     return 0;
 }
 