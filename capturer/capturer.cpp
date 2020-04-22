/**
 * 该文件用于管理capture，有关capture的输入输出都在内部完成
 * 
 */

#include "capturer.h"
#include "capture_api.h"
#include <thread>

// std::map<std::string, std::thread> threads;

char errbuf[PCAP_ERRBUF_SIZE];
// void getInterface(){
//     std::vector<NetInterface> alldevs_vec;
//     if(get_alldevs(alldevs_vec, errbuf)==PCAP_ERROR)
//     {
//         Debug("%s",errbuf);
//         exit(-1);
//     }
//     show_alldevs(alldevs_vec);
//     Debug("alldevs_vec size = %d", (int)alldevs_vec.size());
// }

// void stop(std::string interface)
// {
//     std::thread t = threads.find(interface);
// }


// // 创造新线程
// void run(std::string interface)
// {
//     std::thread t(interface_live,interface);
//     threads.insert(interface, t);
//     t.join();
// }

void output_dev()
{
    std::vector<NetInterface> devs_vec;
    get_alldevs(devs_vec,errbuf);
    show_alldevs(devs_vec);
}

void run(std::string interface_name)
{
    std::cout<<interface_name<<std::endl;
}

void run()
{
    output_dev();
}