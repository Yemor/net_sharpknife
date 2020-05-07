#include "eth.h"
#include "../ipv4/ipv4.h"

namespace analyzer
{
namespace eth
{
ETH_Analyzer::ETH_Analyzer() {}
ETH_Analyzer::~ETH_Analyzer() {}
void ETH_Analyzer::DeliverPacket(std::string data, json11::Json::array &analyzer_data,
                                 analyzer_manager::analyzer_status &status, int &cnt)
{
    SN_Debug("in Eth_Analyzer, get data, data_length = %lu", data.length());
    if (data.length() > 14)
    {
        std::vector<char> src_vec;
        std::vector<char> dst_vec;
        do
        {
            unsigned char tmp = data[cnt];
            src_vec.push_back(conv_hex(tmp >> 4));
            src_vec.push_back(conv_hex(tmp & 15));
            if (cnt != 5)
                src_vec.push_back(':');
            cnt++;
        } while (cnt < 6);
        do
        {
            unsigned char tmp = data[cnt];
            dst_vec.push_back(conv_hex(tmp >> 4));
            dst_vec.push_back(conv_hex(tmp & 15));
            if (cnt != 11)
                dst_vec.push_back(':');
            cnt++;
        } while (cnt < 12);
        std::string src_mac = std::string(src_vec.begin(), src_vec.end()).c_str();
        std::string dst_mac = std::string(dst_vec.begin(), dst_vec.end()).c_str();
        // status = analyzer_manager::ANALYZER_FINISH;

        //IPv4或IPv6判断
        do
        {
            unsigned char tmp1 = data[cnt];
            char up1 = conv_hex(tmp1 >> 4);
            char down1 = conv_hex(tmp1 & 15);
            unsigned char tmp2 = data[cnt + 1];
            char up2 = conv_hex(tmp2 >> 4);
            char down2 = conv_hex(tmp2 & 15);
            SN_Debug(" %c%c %c%c test ", up1, down1, up2, down2);
        } while (cnt < 12);
        uint16_t eth_type = ntohs(*(uint16_t *)(data.c_str() + cnt));
        cnt+=2;
        SN_Debug("in ip first byte is %u", eth_type);
        if (eth_type == 0x0800)
        {
            status = analyzer_manager::ANALYZER_IPV4;
            /* code */
            // ipv4::IPV4_Analyzer ip_analyzer;
            // ip_analyzer.DeliverPacket(std::string(data.begin() + 14, data.end()), analyzer_data, status);
        }
        else if (eth_type == 0x86dd)
        {
            status = analyzer_manager::ANALYZER_IPV6;
            /* code */
            SN_Debug("ipv6 in eth_analyzer");
        }
        else
        {
            status = analyzer_manager::ANALYZER_FAIL;
            /* code */
            SN_Debug("unsupport in eth_analyzer");
        }
        json11::Json::array eth_data;
        eth_data.push_back(json11::Json::object{{"协议", "ethernet"}});
        eth_data.push_back(json11::Json::object{{"源MAC地址", src_mac}});
        eth_data.push_back(json11::Json::object{{"目的MAC地址", dst_mac}});
        eth_data.push_back(json11::Json::object{{"下一协议", eth_type == 0x0800 ? "ipv4" : (eth_type == 0x86dd ? "ipv6" : "other")}});
        analyzer_data.push_back(eth_data);
        return;
    }
    else
    {
        status = analyzer_manager::ANALYZER_FAIL;
        return;
    }

    // if (bytes.length() > 14)
    // {
    //     std::vector<char> src_vec;
    //     int cnt = 0;
    //     do
    //     {
    //         unsigned char tmp = bytes[cnt];
    //         src_vec.push_back(conv_hex(tmp >> 4));
    //         src_vec.push_back(conv_hex(tmp & 15));
    //         src_vec.push_back(' ');
    //         cnt++;
    //     } while (cnt % 16 != 0 && cnt < 6);
    //     std::string src_mac = std::string(src_vec.begin(), src_vec.end()).c_str();
    //     std::vector<char> dst_vec;
    //     int cnt = 6;
    //     do
    //     {
    //         unsigned char tmp = bytes[cnt];
    //         dst_vec.push_back(conv_hex(tmp >> 4));
    //         dst_vec.push_back(conv_hex(tmp & 15));
    //         dst_vec.push_back(' ');
    //         cnt++;
    //     } while (cnt % 16 != 0 && cnt < 12);
    //     std::string dst_mac = std::string(dst_vec.begin(), dst_vec.end()).c_str();
    //     std::cout << "src MAC = " << src_mac << std::endl;
    //     std::cout << "dst MAC = " << dst_mac << std::endl;
    //     std::cout << "ip protocol = " << bytes[12] * 255 + bytes[13] << std::endl;
    // }
}
} // namespace eth
} // namespace analyzer