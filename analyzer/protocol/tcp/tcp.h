#ifndef SHARPKNIFE_ANALYZER_ANALYZER_TCP
#define SHARPKNIFE_ANALYZER_ANALYZER_TCP

#include "../../analyzer.h"
#include <sstream>

namespace analyzer
{
namespace tcp
{

enum{
    HTTP=80,
    
};

class TCP_Analyzer : public analyzer::Analyzer
{
public:
    TCP_Analyzer();
    virtual ~TCP_Analyzer();
    void DeliverPacket(std::string data, json11::Json::array &analyzer_data,
                       analyzer_manager::analyzer_status &status, int &cnt);

protected:
    //SRC_IP:SRC_PORT, DST_IP:DST_PORT
    static std::map<std::string, std::map<std::string, std::string>> fragment;
};
} // namespace eth

} // namespace analyzer

#endif