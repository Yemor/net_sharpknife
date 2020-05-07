#ifndef SHARPKNIFE_ANALYZER_ANALYZER_MANAGER
#define SHARPKNIFE_ANALYZER_ANALYZER_MANAGER

#include "../sharpknife_common.h"
#include "../json11.hpp"

namespace analyzer_manager
{

enum analyzer_status
{
    //DATALINK
    ANALYZER_ETH,
    //NEWWORK
    ANALYZER_IPV4,
    ANALYZER_IPV6,
    //TRANSLATE
    ANALYZER_ICMP,
    ANALYZER_TCP,
    ANALYZER_UDP,
    ANALYZER_UNKNOW,
    ANALYZER_FAIL,
    ANALYZER_WAIT,
    ANALYZER_FINISH
};

class Analyzer_Manager
{
public:
    Analyzer_Manager();
    virtual ~Analyzer_Manager();
    void DeliverStream(std::string data);

protected:
    static int am_cnt;
    static int am_call_cnt;
    //member_data
};

} // namespace analyzer_manager

#endif