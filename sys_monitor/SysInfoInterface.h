#pragma once
#ifndef SYSINFOINTERFACE_H
#define SYSINFOINTERFACE_H

#include <WinSock2.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
using::std::string;
using::std::vector;
using::std::map;
using::std::cout;
using::std::endl;


#ifdef _WIN32
#include <Iphlpapi.h>
#include <Pdh.h>
#include <PdhMsg.h>
#include <stdio.h>
#include <VersionHelpers.h>
#endif

#ifdef  __linux__
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include "stringutils.h"
#include <fstream>
#include <list>
#include <string>
#include <sys/stat.h>
#include "sysinfo.h"
#define NET_INFO_PATH "/proc/net/dev"
#define NET_DIFF_TIME 1
#endif

//#define qulonglong unsigned long long int;

#ifdef __linux__
    typedef unsigned long DWORD;
    typedef unsigned long long DWORD64;
#endif

typedef struct _FILETIME FILETIME;
typedef unsigned long long int qulonglong;
typedef unsigned long DWORD;
typedef unsigned long long DWORD64;

//网卡信息结构体
struct NetCardInfo
{
    string mac_description;
    string ip_address;
    string ip_mask;
    string mac_address;
};


/*
    Name：           系统信息监控类

    Description：    包含设备cpu men os等基本信息获取函数
                     包含获取网卡 上下行等相关信息函数
                     部分代码不是自己写功能尚不明确

    Test：           实现文件尚未进行测试
*/
class SysInfo
{
public:
    SysInfo();
    ~SysInfo();

    void init();
    double cpuLoadAverage();
    double memoryUsed();

    /*
        暂定
    */
    vector<qulonglong> cpuRawData();
    qulonglong convertFileTime(const FILETIME& filetime) const;

    /*
        设备cpu men os信息
    */
    // 静态信息
    static string sys_static_cpu_info();// 获得 CPU描述信息
    static string sys_static_mem_info();// 获得 MEM描述信息
    static string sys_static_os_info(); // 获得 OS描述信息
    static string sys_static_host_name(); // 获得 hostname
    // 动态信息
    static double sys_cpu_usage();// 获得 CPU 利用率
    static double sys_mem_usage();// 获得 MEM 利用率
    static double sys_net_usage();// 获得 NET 利用率

    /*
        网卡信息
    */
    static void GetAllAdapterInfo(); //获取所有网卡名称							
    static void GetSpeed(string netcardname);		     //获取网卡速度						
    static void GetSysNetworkFlow(); //获取上下行流量	
    static int ReturnSendSpeed();    //返回上行速度
    static int ReturnResvSpeed();    //返回下行速度
    static int ReturnSend();         //返回上行总流量
    static int ReturnResv();         //返回下行总流量
    static map<string, NetCardInfo> ReturnNetcardInfo();  //返回网卡名称
    static std::string replace_all_distinct(std::string& str, const std::string& old_value, const std::string& new_value);//windows下监控 替换正确格式网卡名
    static void Reset();

private:
    SysInfo(const SysInfo& copy_destructor);
    SysInfo& operator=(const SysInfo& overide_equal);

    vector<qulonglong> mCpuLoadLastValues;

    /*
        网卡信息相关定义
    */
    static map<string, NetCardInfo> net_card_info_;
    static DWORD resv_speed_;							
    static DWORD send_speed_;							
    static DWORD64 resv_total_;							
    static DWORD64 send_total_;							
    static DWORD64 resv_total_pre_;
    static  DWORD64 send_total_pre_;
    static time_t net_previous_timeStamp_;  //记录上一次系统时间戳   时间单位:秒
    static time_t net_current_timeStamp_;   //记录当前系统时间戳 时间单位:秒
    static double net_dif_time_;            //记录时间差 时间单位:秒
    static int count;
};

#endif // SYSINFOINTERFACE_H
