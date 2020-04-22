/**
 * 网络接口类
 * 
 */

#ifndef SHARPKNIFE_NET_INTERFACE
#define SHARPKNIFE_NET_INTERFACE

#include "../sharpknife_common.h"

class NetInterface
{
private:
    std::string dev_name_;
    std::string dev_descript_;
    bpf_u_int32 flags_;

public:
    NetInterface(pcap_if_t *net_interface);
    ~NetInterface();
    std::string dev_name() { return dev_name_; };
    std::string dev_descript() { return dev_descript_; };
    bpf_u_int32 dev_flag() { return flags_; }
};

#endif