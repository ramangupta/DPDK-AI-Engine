#include <stdio.h>
#include <rte_eal.h>
#include <rte_ethdev.h>

int main(int argc, char **argv) {
    int ret;
    uint16_t port_id;
    uint16_t nb_ports;

    // Initialize DPDK EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    // Count available ports
    nb_ports = rte_eth_dev_count_avail();
    printf("Number of available Ethernet ports: %u\n", nb_ports);

    // Print info for each port
    RTE_ETH_FOREACH_DEV(port_id) {
        struct rte_eth_dev_info dev_info;
        rte_eth_dev_info_get(port_id, &dev_info);

        const char *dev_name = rte_dev_name(dev_info.device);

        printf("Port %u: driver=%s, name=%s\n",
               port_id,
               dev_info.driver_name ? dev_info.driver_name : "unknown",
               dev_name ? dev_name : "unknown");
    }

    return 0;
}
