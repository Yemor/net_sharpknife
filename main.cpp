/**
 * 该文件为启动文件，用于调用capture等组件中的内容
 */

#include "sharpknife_common.h"
#include "./capturer/capturer.h"
#include "dbconnect/dbconnect_api.h"
#include "analyzer/analyzer_manager.h"
#include <iostream>

int main()
{
    std::string dev_name;
    SN_Debug("Start Program.");
    run();
    printf("Please input the dev you wanna:");
    std::cin>>dev_name;
    //创建数据库连接
    // up_init();
    run(dev_name);
    SN_Debug("Finish Program.");

    return 0;
}