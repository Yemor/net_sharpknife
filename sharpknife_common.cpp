#include "sharpknife_common.h"
#include "json11.hpp"

void set_string(std::string &key, char *value)
{
    key = value?value:"";
}

char conv_hex(unsigned int d)
{
    if(d<10)
    {
        return '0'+d;
    }
    else if(d<16)
    {
        return 'a'+d-10;
    }
    else return '#';
}

// void read_json(FILE *)
// {
//     json11::JsonParse()
// }