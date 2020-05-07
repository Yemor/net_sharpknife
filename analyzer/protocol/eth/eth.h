#ifndef SHARPKNIFE_ANALYZER_ANALYZER_ETH
#define SHARPKNIFE_ANALYZER_ANALYZER_ETH

#include "../../analyzer.h"

namespace analyzer
{
namespace eth
{
class ETH_Analyzer : public analyzer::Analyzer
{
public:
    ETH_Analyzer();
    virtual ~ETH_Analyzer();
    void DeliverPacket(std::string data, json11::Json::array &analyzer_data,
                       analyzer_manager::analyzer_status &status, int &cnt);

protected:
};
} // namespace eth

} // namespace analyzer

#endif