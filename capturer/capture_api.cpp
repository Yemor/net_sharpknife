#include "capture_api.h"
#include "capturer.h"

int get_alldevs(std::vector<NetInterface> &alldevs_vec, char *errbuf)
{
    pcap_if_t *alldevs = NULL;
    pcap_if_t *dev = NULL;
    int i;
    if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR)
    {
        if (errbuf != NULL)
        {
            SN_Debug("%s", errbuf);
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
    for (int i = 0; i < alldevs_vec.size(); i++)
    {
        SN_Debug("   dev %d : dev_name = %s, dev_descript = %s, dev_flags = %d", 
                            i+1,
                            alldevs_vec[i].dev_name().c_str(), 
                            alldevs_vec[i].dev_descript().c_str(), 
                            alldevs_vec[i].dev_flag());
    }
}

/**
 * @brief 回调数据库写入
 * 
 * @param bytes 数据二进制文本内容
 */
void recall_db(std::string bytes)
{
    db_write(bytes);
}

/**
 * @brief 抓包回调
 * 
 * 
 */
void deliver_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    SN_Debug("recevice data caplen=%d len=%d ts=%lld\n", h->caplen, h->len, h->ts.tv_sec * 1000000LL + h->ts.tv_usec);
    int cnt = 0;
    std::vector<char> total_vec;
    while (cnt < h->caplen)
    {
        std::vector<char> vec;
        do
        {
            unsigned char tmp = *(bytes + cnt);
            vec.push_back(conv_hex(tmp >> 4));
            vec.push_back(conv_hex(tmp & 15));
            vec.push_back(' ');
            cnt++;
        } while (cnt % 16 != 0 && cnt < h->caplen);
        SN_Debug("%s", std::string(vec.begin(), vec.end()).c_str());
        total_vec.insert(total_vec.end(), vec.begin(), vec.end());
    }
    SN_Debug("\n");
    recall_db(std::string(total_vec.begin(), total_vec.end()));
    return;
}

/**
 * @brief 监听
 * 
 * @param snaplen 最大抓取数据包的长度
 * @param promisc 混杂模式
 * @param timeout 读取超时时长
 * @param device_name
 * @param errbuf
 * 
 */
int interface_live(int snaplen, int promisc, int timeout, std::string device_name, char *errbuf)
{
    pcap_t *device = NULL;
    SN_Debug("try to create pcap");
    if ((device = pcap_open_live(device_name.c_str(), snaplen, promisc, timeout, errbuf)) == NULL)
    {
        SN_Debug("pcap_open_live(%s) error, %s\n", device_name.c_str(), errbuf);
        return PCAP_ERROR;
    }
    SN_Debug("begin read_data");
    int dispatch_status = 0;
    // u_char user[100] = "ymr";
    pcap_handler a = deliver_packet;
    for (int i = 1; i <= 100 && dispatch_status != -1; i++)
    {
        SN_Debug("pcap %d:", i);
        dispatch_status = pcap_dispatch(device, 1, a, NULL);
    }
    SN_Debug("try to close dev");
    pcap_close(device);
    return 0;
}
