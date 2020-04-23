#ifndef SHARPKNIFE_DBCONNECT_DBCONNECT
#define SHARPKNIFE_DBCONNECT_DBCONNECT

#include <string>
#include "../sharpknife_common.h"
#include "../json11.hpp"



void db_write(std::string bytes);

const int DBWRITE_RAW_DATA = 1;

#endif