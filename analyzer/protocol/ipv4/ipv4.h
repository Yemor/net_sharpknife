#ifndef SHARPKNIFE_ANALYZER_ANALYZER_IPV4
#define SHARPKNIFE_ANALYZER_ANALYZER_IPV4

#include "../../analyzer.h"
#include <sstream>

namespace analyzer
{
namespace ipv4
{

enum protocol{
    ICMP=1,
    IGMP,
    GGP,
    IP,
    ST,
    TCP,
    CBT,
    EGP,
    IGP,
    BBN,
    NVP2,
    PUP,
    ARGUS,
    EMCON,
    XNET,
    CHAOS,
    UDP,
    MUX,
    DCN_MEAS,
    HMP,
};
class IPV4_Analyzer : public analyzer::Analyzer
{
public:
    IPV4_Analyzer();
    virtual ~IPV4_Analyzer();
    void DeliverPacket(std::string data, json11::Json::array &analyzer_data,
                       analyzer_manager::analyzer_status &status, int &cnt);

protected:
    static std::map<std::string, std::map<std::string, std::string>> fragment;
};
} // namespace eth

} // namespace analyzer

#endif