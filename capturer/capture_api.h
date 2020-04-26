#ifndef SHARPKNIFE_CAPTURE_API
#define SHARPKNIFE_CAPTURE_API

/**
 * sharpknife调用libpcap获取网络接口API
 * 
 */

#include "../sharpknife_common.h"
#include "net_interface.h"


int get_alldevs(std::vector<NetInterface> &alldevs_vec, char *errbuf);

void show_alldevs(std::vector<NetInterface> &alldevs_vec);

void recall_db(std::string bytes);

void recall_analyzer(std::string bytes);

void deliver_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

int interface_live(int snaplen, int promisc, int timeout, std::string device_name, char *errbuf);


#endif