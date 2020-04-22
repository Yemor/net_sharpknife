#include "capture_api.h"


int get_alldevs(std::vector<NetInterface> &alldevs_vec, char *errbuf)
{
    pcap_if_t *alldevs = NULL;
    pcap_if_t *dev = NULL;
    int i;
    if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR)
    {
        if (errbuf != NULL)
        {
            Debug("%s", errbuf);
        }
        return PCAP_ERROR;
    }
    for (i = 0, dev = alldevs; dev; dev = dev->next)
    {
        alldevs_vec.push_back(NetInterface(dev));
        // Debug("\n"
        //       "   #dev %d: \n"
        //       "       name:%s\n"
        //       "       (%s)\n"
        //       "       (%s)\n",
        //       ++i, dev->name ? dev->name : "",
        //       dev->description ? dev->description : "",
        //       dev->flags);
    }
    pcap_freealldevs(alldevs);
    return 0;
}

void show_alldevs(std::vector<NetInterface> &alldevs_vec)
{
    for(int i=0;i<alldevs_vec.size();i++)
    {
        Debug(" dev %d",i);
        Debug("     dev_name %s",alldevs_vec[i].dev_name().c_str());
        Debug("     dev_descript %s",alldevs_vec[i].dev_descript().c_str());
        Debug("     dev_flags %d",alldevs_vec[i].dev_flag());
    }
}

void deliver_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    Debug("recevice data caplen=%d len=%d ts=%lld\n", h->caplen, h->len, h->ts.tv_sec*1000000LL+h->ts.tv_usec);
    int cnt = 0;
    while(cnt<h->caplen)
    {
        std::vector<char> vec;
        do{
            unsigned char tmp = *(bytes+cnt);
            vec.push_back(conv_hex(tmp>>4));
            vec.push_back(conv_hex(tmp&15));
            vec.push_back(' ');
            cnt++;
        }while(cnt%16!=0&&cnt<h->caplen);
        Debug("%s",std::string(vec.begin(),vec.end()).c_str());
    }
    return;
}

int interface_live(int snaplen, int promisc, int timeout, std::string device_name, char *errbuf)
{
    pcap_t *device = NULL;
    Debug("try to create pcap");
    if((device = pcap_open_live(device_name.c_str(), snaplen, promisc, timeout, errbuf)) == NULL)
    {
        Debug("pcap_open_live(%s) error, %s\n", device_name.c_str(), errbuf);
    }
    Debug("begin read_data");
    int dispatch_status = 0;
    // u_char user[100] = "ymr";
    pcap_handler a = deliver_packet;
    for (int i = 1; i <= 100 && dispatch_status!=-1; i++)
    {
        Debug("pcap %d:",i);
        dispatch_status = pcap_dispatch(device, 1, a, NULL);
    }
    Debug("try to close dev");
    pcap_close(device);
    return 0;
}
