#include "ipv4.h"

namespace analyzer
{
namespace ipv4
{
std::map<std::string, std::map<std::string, std::string>> IPV4_Analyzer::fragment;
IPV4_Analyzer::IPV4_Analyzer() {}
IPV4_Analyzer::~IPV4_Analyzer() {}
void IPV4_Analyzer::DeliverPacket(std::string data, json11::Json::array &analyzer_data,
                                  analyzer_manager::analyzer_status &status, int &cnt)
{
    
    std::string src_mac = analyzer_data[0]["src_mac"].string_value();
    std::string dst_mac = analyzer_data[0]["dst_mac"].string_value();
    data = this->fragment[src_mac][dst_mac] + data;
    SN_Debug("ipv4 in eth_analyzer");
    SN_Debug("in IPV4_Analyzer, get data, data_length = %lu", data.length());
    if (data.length() > 20)
    {
        uint16_t ipv4_h1 = ntohs(*(uint16_t *)(data.c_str() + cnt));
        cnt += 2;
        SN_Debug("first bytes is %u", ipv4_h1);
        uint8_t ver = ipv4_h1 >> 12;
        uint8_t header_len = ((ipv4_h1 & 0x0f00) >> 8) * 4; //包括option的长度
        uint8_t tos = (ipv4_h1 & 0x78) >> 3;                //differentiated services codepoint, type of service
        uint8_t ip_precedence = ipv4_h1 & 0x07;             //ip_precedence
        SN_Debug("ver = %u, header_len = %u", ver, header_len);
        SN_Debug("tos = %u, ip_precedence = %u", tos, ip_precedence);

        uint16_t tot_len = ntohs(*(uint16_t *)(data.c_str() + cnt));

        cnt += 2;
        uint16_t identify = ntohs(*(uint16_t *)(data.c_str() + cnt)); //identification
        cnt += 2;
        SN_Debug("tot_len = %u, identification = %#x", tot_len, identify);
        uint16_t flag = ntohs(*(uint16_t *)(data.c_str() + cnt));
        cnt += 2;
        bool reserved_bit = (flag & (0x1 << 15)) ? true : false;
        bool dont_fragment = (flag & (0x1 << 14)) ? true : false;
        bool more_fragment = (flag & (0x1 << 13)) ? true : false;
        uint16_t fragment_offset = flag & (0x1fff);
        if(more_fragment)
        {
            if(tot_len > data.length())
            {
                status = analyzer_manager::ANALYZER_WAIT;
                this->fragment[src_mac][dst_mac] += data;
            }
            else
            {
                status = analyzer_manager::ANALYZER_FAIL;
            }
            return;
        }
        else if(dont_fragment)
        {
            this->fragment[src_mac][dst_mac].clear();
        }
        else
        {
            // dont_fragment 和 more_fragment之间必定有一个为1
            status = analyzer_manager::ANALYZER_FAIL;
            return ;
        }
        if (tot_len > data.length())
        {
            if (more_fragment)
            {
                std::string src_mac = analyzer_data[0]["src_mac"].string_value();
                std::string dst_mac = analyzer_data[0]["dst_mac"].string_value();
                status = analyzer_manager::ANALYZER_WAIT;
                this->fragment[src_mac][dst_mac] += data;
            }
            else
            {
                status = analyzer_manager::ANALYZER_FAIL;
            }
            return;
        }
        else if ((!dont_fragment) || more_fragment)
        {
            status = analyzer_manager::ANALYZER_FAIL;
            return;
        }
        SN_Debug("reserved_bit = %s, dont_fragment = %s", reserved_bit ? "true" : "false", dont_fragment ? "true" : "false");
        SN_Debug("more_fragment = %s, fragment_offset = %u", more_fragment ? "true" : "false", fragment_offset);
        uint8_t ttl = *(uint8_t *)(data.c_str() + cnt);
        cnt++;
        uint8_t next_ptc = *(uint8_t *)(data.c_str() + cnt); //next_protocol
        cnt++;
        uint16_t checksum = ntohs(*(uint16_t *)(data.c_str() + cnt));
        cnt += 2;
        SN_Debug("ttl = %d, next_protocol = %d, checksum = %#x", ttl, next_ptc, checksum);
        uint32_t src_ip = ntohl(*(uint32_t *)(data.c_str() + cnt));
        cnt += 4;
        uint32_t dst_ip = ntohl(*(uint32_t *)(data.c_str() + cnt));
        cnt += 4;
        SN_Debug("src_ip = %u.%u.%u.%u, dst_ip = %u.%u.%u.%u", (src_ip >> 24) & 0xff, (src_ip >> 16) & 0xff, (src_ip >> 8) & 0xff, src_ip & 0xff,
                 (dst_ip >> 24) & 0xff, (dst_ip >> 16) & 0xff, (dst_ip >> 8) & 0xff, dst_ip & 0xff);
        std::stringstream sstream;
        std::string src_ip_str, dst_ip_str;
        sstream << ((src_ip >> 24) & 0xff) << "." << ((src_ip >> 16) & 0xff) << "." << ((src_ip >> 8) & 0xff) << "." << (src_ip & 0xff);
        src_ip_str = sstream.str();
        sstream.str("");
        sstream << ((dst_ip >> 24) & 0xff) << "." << ((dst_ip >> 16) & 0xff) << "." << ((dst_ip >> 8) & 0xff) << "." << (dst_ip & 0xff);
        dst_ip_str = sstream.str();
        sstream.str("");
        //ip_option
        cnt = tot_len;
        std::string protocol_name;
        switch (next_ptc)
        {
        case ICMP:
            status = analyzer_manager::ANALYZER_ICMP;
            protocol_name = "icmp";
            break;
        case TCP:
            status = analyzer_manager::ANALYZER_TCP;
            protocol_name = "tcp";
            break;
        case UDP:
            status = analyzer_manager::ANALYZER_UDP;
            protocol_name = "udp";
            break;
        default:
            status = analyzer_manager::ANALYZER_UNKNOW;
            protocol_name = "unknow";
            break;
        }
        json11::Json::array ipv4_data;
        ipv4_data.push_back(json11::Json::object{{"协议", "ipv4"}});
        ipv4_data.push_back(json11::Json::object{{"ipv4版本", ver}});
        ipv4_data.push_back(json11::Json::object{{"ipv4头部长度", header_len}});
        ipv4_data.push_back(json11::Json::object{{"服务类型", tos}});
        ipv4_data.push_back(json11::Json::object{{"IP优先级", ip_precedence}});
        ipv4_data.push_back(json11::Json::object{{"数据报总长度", tot_len}});
        ipv4_data.push_back(json11::Json::object{{"是否不分片", dont_fragment}});
        ipv4_data.push_back(json11::Json::object{{"后序分片", more_fragment}});
        ipv4_data.push_back(json11::Json::object{{"分片偏移", fragment_offset}});
        ipv4_data.push_back(json11::Json::object{{"存活时间", ttl}});
        ipv4_data.push_back(json11::Json::object{{"下一协议", protocol_name}});
        ipv4_data.push_back(json11::Json::object{{"校验和", checksum}});
        ipv4_data.push_back(json11::Json::object{{"源IP", src_ip_str}});
        ipv4_data.push_back(json11::Json::object{{"校验和", checksum}});
        ipv4_data.push_back(json11::Json::object{{"目的IP", dst_ip_str}});
        analyzer_data.push_back(ipv4_data);
        return;
    }
    else
    {
        status = analyzer_manager::ANALYZER_FAIL;
        return;
    }
}
} // namespace ipv4
} // namespace analyzer