#ifndef SHARPKNIFE_ANALYZER_ANALYZER
#define SHARPKNIFE_ANALYZER_ANALYZER

#include "../sharpknife_common.h"
#include "../json11.hpp"
#include "analyzer_manager.h"

namespace analyzer
{

class Analyzer
{
public:
    Analyzer();
    virtual ~Analyzer();
    // void DeliverStream(std::string data, json11::Json &analyzer_data,
    //                    analyzer_manager::analyzer_status &status);
    // void DeliverPacket(std::string data, json11::Json &analyzer_data,
    //                    analyzer_manager::analyzer_status &status);

protected:
    //member_data
};

} // namespace analyzer

#endif