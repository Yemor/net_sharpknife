#include "net_interface.h"

NetInterface::NetInterface(pcap_if_t *net_interface)
{
    set_string(dev_name_, net_interface->name);
    set_string(dev_descript_, net_interface->description);
    flags_ = net_interface->flags;
}

NetInterface::~NetInterface(){};