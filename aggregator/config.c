#include "aggregator.h"
struct config CONFIG = {
    .pcap_file_name = "synthetic_slf1_flow_num1_count1_seed42.pcap",
    .fw_rules_file_name = "./rules/fw.rules",
    .app = NULL,
    .slf = 1,
    .enable_aggregate = 1,
};

static void init_app(char *app_name) {
  if (strncmp(app_name, "one_way", 8) == 0) {
    CONFIG.app = &one_way_app;
  } else if (strncmp(app_name, "echo", 5) == 0) {
    CONFIG.app = &echo_app;
  } else if (strncmp(app_name, "firewall", 9) == 0) {
    CONFIG.app = &firewall_app;
  } else if (strncmp(app_name, "nat", 4) == 0) {
    CONFIG.app = &nat_app;
  } else if (strncmp(app_name,"chain",6)==0){
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
    } else {
      rte_exit(EXIT_FAILURE, "unrecognized option: %s\n", argv[i]);
    }
  }
}