#include "tcp.h"

namespace analyzer
{
namespace tcp
{
std::map<std::string, std::map<std::string, std::string>> TCP_Analyzer::fragment;
TCP_Analyzer::TCP_Analyzer() {}
TCP_Analyzer::~TCP_Analyzer() {}
void TCP_Analyzer::DeliverPacket(std::string data, json11::Json::array &analyzer_data,
                                 analyzer_manager::analyzer_status &status, int &cnt)
{
    //可以做会话跟踪，通过会话跟踪判断服务端口，通过服务端口判断应用层协议类型
    std::string src_mac = analyzer_data[0]["源MAC地址"].string_value();
    std::string dst_mac = analyzer_data[0]["目的MAC地址"].string_value();
    std::string src_ip = analyzer_data[0]["源IP地址"].string_value();
    std::string dst_ip = analyzer_data[0]["目的IP地址"].string_value();
    std::string src_location = src_mac + ":" + src_ip;
    std::string dst_location = dst_mac + ":" + dst_ip;
    data = this->fragment[src_location][dst_location] + data;
    SN_Debug("ipv4 in eth_analyzer");
    SN_Debug("in TCP_Analyzer, get data, data_length = %lu", data.length());
    if (data.length() > 20)
    {
        uint16_t src_port = ntohs(*(uint16_t *)(data.c_str() + cnt));
        cnt += 2;
        uint16_t dst_port = ntohs(*(uint16_t *)(data.c_str() + cnt));
        cnt += 2;
        SN_Debug("src port = %u, dst port = %u,", src_port, dst_port);
        uint32_t seq_num = ntohs(*(uint32_t *)(data.c_str() + cnt));
        cnt += 4;
        uint32_t ack_num = ntohs(*(uint32_t *)(data.c_str() + cnt));
        cnt += 4;
        uint16_t tcp_h1 = ntohs(*(uint16_t *)(data.c_str() + cnt));
        cnt += 2;
        uint8_t header_len = (tcp_h1 >> 12) * 4;
        uint16_t flags = tcp_h1 & 0x0fff;
        SN_Debug("seq_num = %u, ack_num = %u,", seq_num, ack_num);
        SN_Debug("header_len = %u, flags = %u,", header_len, flags);
        uint16_t win_size = ntohs(*(uint16_t *)(data.c_str() + cnt));
        cnt += 2;
        uint16_t checksum = ntohs(*(uint16_t *)(data.c_str() + cnt));
        cnt += 2;
        uint16_t urgent_ptr = ntohs(*(uint16_t *)(data.c_str() + cnt));
        cnt += 2;

        cnt = header_len;
        analyzer_data.push_back(json11::Json::object{
            {"源端口", src_port},
            {"目的端口", dst_port},
            {"顺序号", (int)seq_num},
            {"响应号", (int)ack_num},
            {"TCP报文长度", header_len},
            {"TCP属性", flags},
            {"滑动窗口大小", win_size},
            {"校验和", checksum},
            {"紧急指针", urgent_ptr}});
        status = analyzer_manager::ANALYZER_FINISH;
        return;
    }
    else
    {
        status = analyzer_manager::ANALYZER_FAIL;
        this->fragment[src_location][dst_location] = "";
        return;
    }
} // namespace tcp
} // namespace tcp
} // namespace analyzer