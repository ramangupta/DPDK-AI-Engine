#include <rte_eal.h>
#include <rte_ethdev.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    printf("Hello, DPDK! 🚀\n");
    return 0;
}

