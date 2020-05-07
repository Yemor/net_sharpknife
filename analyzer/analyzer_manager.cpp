#include "analyzer_manager.h"
#include <map>
#include "analyzer.h"
#include "protocol/eth/eth.h"
#include "protocol/ipv4/ipv4.h"
#include "protocol/tcp/tcp.h"
/**
 * analyzer根据TCP/IP网络模型来划分网络层次，每层必须将本身组成一条完整的信息再给到下一层
 * 每个协议有自己的文件夹和自己的解析规则与类型
 */

namespace analyzer_manager
{

int Analyzer_Manager::am_cnt;

int Analyzer_Manager::am_call_cnt;
Analyzer_Manager::Analyzer_Manager()
{
    am_cnt++;
}

Analyzer_Manager::~Analyzer_Manager() {}

/**
 * 函数作用：交付数据给解析器，并返回解析结果，调用写入数据库的方法
 * 
 * @param
 */
void Analyzer_Manager::DeliverStream(std::string data)
{
    SN_Debug("in Analyzer_Manager, get data, am_cnt = %d, am_call_cnt = %d", am_cnt, ++am_call_cnt);
    // call analyzer deliver and get analyzer_data, analyzer_status
    // if analyzer_status is ANALYZER_WAIT or ANALYZER_FINISH, write analyzer_data to db
    // if analyzer_status is ANALYZER_FAIL, the analyzer data should be clean
    json11::Json::array analyzer_data;
    analyzer_status status = ANALYZER_ETH;
    int precnt = 0, cnt = 0;
    while (status != ANALYZER_FINISH && status != ANALYZER_WAIT && status != ANALYZER_FAIL && status != ANALYZER_UNKNOW)
    {
        switch (status)
        {
        case ANALYZER_ETH:
            static analyzer::eth::ETH_Analyzer eth;
            eth.DeliverPacket(std::string(data.begin()+precnt, data.end()), analyzer_data, status, cnt);
            precnt += cnt;
            cnt = 0;
            break;
        case ANALYZER_IPV4:
            static analyzer::ipv4::IPV4_Analyzer ipv4;
            ipv4.DeliverPacket(std::string(data.begin()+precnt, data.end()), analyzer_data, status, cnt);
            precnt += cnt;
            cnt = 0;
            break;
        case ANALYZER_IPV6:
            /* code */
            break;
        case ANALYZER_TCP:
            static analyzer::tcp::TCP_Analyzer tcp;
            tcp.DeliverPacket(std::string(data.begin()+precnt, data.end()), analyzer_data, status, cnt);
            precnt += cnt;
            cnt = 0;
            break;

        default:
            SN_Debug("%u ", status);
            status = ANALYZER_FINISH;
            break;
        }
    }
    // eth.DeliverPacket(data, analyzer_data, status);
    SN_Debug("in Analyzer_Manager, get analyzer_data = %s ", json11::Json(analyzer_data).dump().c_str());
    if(status == ANALYZER_FINISH)
    {
        //DB_RECALL
    }
}

} // namespace analyzer_manager