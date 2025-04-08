#include "aggregator.h"
struct config CONFIG = {
    .pcap_file_name = "synthetic_slf1_flow_num1_count1_seed42.pcap",
    .fw_rules_file_name = "./rules/fw.rules",
    .app = NULL,
    .slf = 1,
    .enable_aggregate = 0,
    .sender_throughput = -1,
    .ablation = false,
    .access_byte_per_packet = false,
    .miss_penalty_cycle = 0,
};

static void init_app(char *app_name) {
  if (strncmp(app_name, "one_way", 8) == 0) {
    CONFIG.app = &one_way_app;
  } else if (strncmp(app_name, "echo", 5) == 0) {
    CONFIG.app = &echo_app;
  } else if (strncmp(app_name, "chain", 6) == 0) {
    CONFIG.app = &chain_app;
  } else {
    rte_exit(EXIT_FAILURE, "unknown app name %s\n", app_name);
  }
}

void parse_args(int argc, char **argv) {
  if (argc <= 1) {
    CONFIG.app = &echo_app;
    return;
  }

  int i = 1;
  while (i < argc) {
    if (strncmp(argv[i], "--pcap_file", 12) == 0) {
      if (i + 1 >= argc) {
        rte_exit(EXIT_FAILURE, "Not enough argument\n");
      }
      CONFIG.pcap_file_name = argv[i + 1];
      i += 2;

    } else if (strncmp(argv[i], "--fw_rules", 11) == 0) {
      if (i + 1 >= argc) {
        rte_exit(EXIT_FAILURE, "Not enough argument\n");
      }
      CONFIG.fw_rules_file_name = argv[i + 1];
      i += 2;
    } else if (strncmp(argv[i], "--app", 6) == 0) {
      if (i + 1 >= argc) {
        rte_exit(EXIT_FAILURE, "Not enough argument\n");
      }

      init_app(argv[i + 1]);
      i += 2;
    } else if (strncmp(argv[i], "--slf", 6) == 0) {
      if (i + 1 >= argc) {
        rte_exit(EXIT_FAILURE, "Not enough argument\n");
      }

      int slf = atoi(argv[i + 1]);

      if (slf <= 0 || slf > 100) {
        rte_exit(EXIT_FAILURE, "Bad slf=%d\n", slf);
      }
      CONFIG.slf = slf;
      i += 2;
    } else if (strncmp(argv[i], "--enable-aggregator", 20) == 0) {
      if (i + 1 >= argc) {
        rte_exit(EXIT_FAILURE, "not enough argument\n");
      }

      if (argv[i + 1][0] == '0') {
        CONFIG.enable_aggregate = 0;
      } else {
        CONFIG.enable_aggregate = 1;
      }

      i += 2;
    } else if (strncmp(argv[i], "--gbps", 6) == 0) {
      if (i + 1 >= argc) {
        rte_exit(EXIT_FAILURE, "not enough argument\n");
      }
      int gbps = atoi(argv[i + 1]);
      assert(gbps >= 1 && gbps <= 40);
      CONFIG.sender_throughput = gbps;
      printf("targeted sender throughput will be %d Gbps\n",gbps);
      i += 2;

    } else if (strcmp(argv[i], "--access-byte-per-packet") == 0) {
      if (i + 1 >= argc) {
        rte_exit(EXIT_FAILURE, "not enough argument");
      }
      CONFIG.access_byte_per_packet = atoi(argv[i + 1]);
      assert(CONFIG.access_byte_per_packet >= 0);
      i += 2;
    } else if (strcmp(argv[i], "--delay-cycle") == 0) {
      if (i + 1 >= argc) {
        rte_exit(EXIT_FAILURE, "not enough argument");
      }

      CONFIG.miss_penalty_cycle = atoi(argv[i + 1]);
      assert(CONFIG.miss_penalty_cycle >= 0);
      i += 2;
    }else if (strcmp(argv[i], "--ablation") == 0) {
      if (i + 1 >= argc) {
        rte_exit(EXIT_FAILURE, "not enough argument");
      }

      if (argv[i + 1][0] == '1') {
        CONFIG.ablation = true;
      } else {
        CONFIG.ablation = false;
      }
      i += 2;
    } else {
      rte_exit(EXIT_FAILURE, "unrecognized option: %s\n", argv[i]);
    }
  }

  if (CONFIG.sender_throughput == -1) {
    rte_exit(EXIT_FAILURE, "please set the sender throughput\n");
  }
}