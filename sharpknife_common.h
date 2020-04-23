/**
 * sharpknife公用配置及函数
 * 
 */

#ifndef SHARPKNIFE_COMMON_FUNCTION
#define SHARPKNIFE_COMMON_FUNCTION

#include <cstdio>
#include <iostream>
#include <vector>
#include <map>
#include <memory>
#include <string>
#include <pcap.h>

#define SN_Debug(format, ...) fprintf(stderr, "%s:%d: " format "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define SN_Info(format, ...) fprintf(stderr, "%s:%d: " format "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define SN_Error(format, ...) fprintf(stderr, "%s:%d: " format "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define SN_Warn(format, ...) fprintf(stderr, "%s:%d: " format "\n", __FILE__, __LINE__, ##__VA_ARGS__)

void set_string(std::string &key, char *value);

char conv_hex(unsigned int d);
        

#endif