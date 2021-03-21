#pragma warning(disable:4996)
#pragma execution_character_set("utf-8")
#include "SysInfoInterface.h"

#ifdef WIN32
#pragma comment(lib,"Iphlpapi.lib") //需要Iphlpapi.lib库
#endif


static const  int ADAPTERNUM = 10;
map<string, NetCardInfo> SysInfo::net_card_info_;
DWORD SysInfo::resv_speed_;							//下行速度
DWORD SysInfo::send_speed_;							//上行速度
DWORD64 SysInfo::resv_total_;						//下行总流量
DWORD64 SysInfo::send_total_;						//上行总流量


DWORD64 SysInfo::resv_total_pre_;
DWORD64 SysInfo::send_total_pre_;
time_t SysInfo::net_previous_timeStamp_;
time_t SysInfo::net_current_timeStamp_;
double SysInfo::net_dif_time_;
int SysInfo::count = 1;

//用于存储结构体cards
NetCardInfo cards[ADAPTERNUM];

SysInfo sys;

void SysInfo::init()
{
    mCpuLoadLastValues = cpuRawData();
}

vector<qulonglong> SysInfo::cpuRawData()
{
#ifdef WIN32
    FILETIME idleTime;
    FILETIME kernelTime;
    FILETIME userTime;

    GetSystemTimes(&idleTime, &kernelTime, &userTime);

    vector<qulonglong> rawData;

    rawData.push_back(convertFileTime(idleTime));
    rawData.push_back(convertFileTime(kernelTime));
    rawData.push_back(convertFileTime(userTime));
    return rawData;
#endif // WIN32

#ifdef __linux__
    FILE* fd;
    char* lineptr = NULL;
    size_t n = 0;
    fd = fopen("/proc/stat", "r");
    if (fd == NULL) {
        exit(EXIT_FAILURE);
    }
    getline(&lineptr, &n, fd);
    const char* line = lineptr;

    qulonglong totalUser = 0, totalUserNice = 0, totalSystem = 0, totalIdle = 0;
    std::sscanf(line, "cpu %llu %llu %llu %llu",
        &totalUser, &totalUserNice, &totalSystem, &totalIdle);

    vector<qulonglong> rawData;
    rawData.push_back(totalUser);
    rawData.push_back(totalUserNice);
    rawData.push_back(totalSystem);
    rawData.push_back(totalIdle);

    if (lineptr) {
        free(lineptr);
    }

    return rawData;
#endif // __linux__
}

double SysInfo::cpuLoadAverage()
{
#ifdef WIN32
    vector<qulonglong> firstSample = mCpuLoadLastValues;
    vector<qulonglong> secondSample = cpuRawData();
    mCpuLoadLastValues = secondSample;

    qulonglong currentIdle = secondSample[0] - firstSample[0];
    qulonglong currentKernel = secondSample[1] - firstSample[1];
    qulonglong currentUser = secondSample[2] - firstSample[2];
    qulonglong currentSystem = currentKernel + currentUser;

    double percent = (currentSystem - currentIdle) * 100.0 / currentSystem;
    return max(0.0, min(percent, 100.0));
#endif // WIN32

#ifdef __linux__
    vector<qulonglong> firstSample = mCpuLoadLastValues;
    vector<qulonglong> secondSample = cpuRawData();
    mCpuLoadLastValues = secondSample;

    double overall = (secondSample[0] - firstSample[0])
        + (secondSample[1] - firstSample[1])
        + (secondSample[2] - firstSample[2]);

    double total = overall + (secondSample[3] - firstSample[3]);
    double percent = (overall / total) * 100.0;
    return max(0.0, min(percent, 100.0));
#endif // __linux__


}

double SysInfo::memoryUsed()
{
#ifdef WIN32
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memoryStatus);
    qulonglong memoryPhysicalUsed = memoryStatus.ullTotalPhys - memoryStatus.ullAvailPhys;
    return (double)memoryPhysicalUsed / (double)memoryStatus.ullTotalPhys * 100.0;
#endif // WIN32

#ifdef __linux__
    struct sysinfo memInfo;
    sysinfo(&memInfo);

    qulonglong totalMemory = memInfo.totalram;
    totalMemory += memInfo.totalswap;
    totalMemory *= memInfo.mem_unit;

    qulonglong totalMemoryUsed = memInfo.totalram - memInfo.freeram;
    totalMemoryUsed += memInfo.totalswap - memInfo.freeswap;
    totalMemoryUsed *= memInfo.mem_unit;

    double percent = (double)totalMemoryUsed / (double)totalMemory * 100.0;
    return max(0.0, min(percent, 100.0));
#endif // __linux__
}

//windows only
qulonglong SysInfo::convertFileTime(const FILETIME& filetime) const
{
    ULARGE_INTEGER largeInteger;
    largeInteger.LowPart = filetime.dwLowDateTime;
    largeInteger.HighPart = filetime.dwHighDateTime;
    return largeInteger.QuadPart;
}



string SysInfo::sys_static_cpu_info()
{
#ifdef WIN32
    string m_cpuDescribe;
    long lRet;
    HKEY hKey;
    TCHAR tchData[1000];
    DWORD dwSize;
    // 打开注册表(if open the regedit succeed,the function return ERROR_SUCCESS which define
    // in WINERROR.H and equal to 0);
    // 如果函数调用成功，则返回0（ERROR_SUCCESS）。
    // 否则，返回值为文件WINERROR.h中定义的一个非零的错误代码。

    lRet = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE, // 主键 PrimaryKey
        "Hardware\\Description\\System\\CentralProcessor\\0", //子健 subkey
        0,
        KEY_QUERY_VALUE, // 允许查询子健 allow to query the subkey
        &hKey
    );

    if (lRet == ERROR_SUCCESS)
    {
        // 查询注册表(Query the regedit)
        dwSize = 1000; // 这里是预留大小，不然会溢出造成 RegQueryValueExW return 234; if dwSize is not big enough,RegQueryValueExW will return 234;
        lRet = RegQueryValueEx(
            hKey,
            "ProcessorNameString", // 子健的名称 subkey
            0,
            0,
            (LPBYTE)tchData, // 用于装载指定值的一个缓冲区 get data from the buffer
            &dwSize); // 如果查询成功,dwSize将得到实际装载到缓冲区的字节数 it's value equal to the length of tchData;

        if (lRet == ERROR_SUCCESS)
        {
            return m_cpuDescribe = tchData;
        }
        else
        {
            return m_cpuDescribe = "Unknown CPU";
        }
        RegCloseKey(hKey);
    }
    return m_cpuDescribe = "Can't find CPU";
#endif
#ifdef __linux__
    FILE* fp;
    char buffer[100];
    fp = popen("cat /proc/cpuinfo | grep name | cut -f2 -d: |uniq", "r");
    fgets(buffer, sizeof(buffer), fp);
    string out = buffer;
    string cpuinfo = trim(out.substr(0, out.size()));
    pclose(fp);
    return cpu_info;
#endif
}

string SysInfo::sys_static_mem_info()
{
#ifdef WIN32
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    double m_totalMem = statex.ullTotalPhys * 1.0 / 1024000000;
    double m_freeMem = statex.ullAvailPhys * 1.0 / 1024000000;
    char buffer1[20];
    sprintf(buffer1, "%.2f", m_totalMem - m_freeMem);
    char buffer2[20];
    sprintf(buffer2, "%.2f", m_totalMem);
    string str1 = buffer1;
    string str2 = buffer2;
    string m_memDescribe = "Used " + str1 + " GB / ALL " + str2 + " GB";

    return m_memDescribe;
#endif // WIN32
#ifdef __linux__
    FILE* fp;
    char buffer[100];
    fp = popen("cat /proc/meminfo", "r");
    fgets(buffer, sizeof(buffer), fp);
    string out = buffer;
    string::size_type posEnd = out.find(':');
    string meminfo = trim(out.substr(posEnd + 1, out.size()));
    pclose(fp);
    return meminfo;
#endif
}

string SysInfo::sys_static_os_info()
{
#ifdef WIN32
    string m_osDescribe;

    /*
    * WINAPI提供的GetVersionEx只能判断win8以下系统 因此先判断是否为8级8以上系统
    * 
    * 需要在工程中加入manifest文件
    * 内容：
        <!-- example.exe.manifest -->
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
            <assemblyIdentity
                type="win32"
                name="Contoso.ExampleApplication.ExampleBinary"
                version="1.2.3.4"
                processorArchitecture="x86"
            />
            <description>Contoso Example Application</description>
            <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
                <application>
                    <!-- Windows 10 -->
                    <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
                    <!-- Windows 8.1 -->
                    <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
                    <!-- Windows 8 -->
                    <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
                    <!-- Windows 7 -->
                    <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
                    <!-- Windows Vista -->
                    <supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"/> 
                </application>
            </compatibility>
            <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
                <security>
                    <requestedPrivileges>
                        <!--
                          UAC settings:
                          - app should run at same integrity level as calling process
                          - app does not need to manipulate windows belonging to
                            higher-integrity-level processes
                          -->
                        <requestedExecutionLevel
                            level="asInvoker"
                            uiAccess="false"
                        />   
                    </requestedPrivileges>
                </security>
            </trustInfo>
        </assembly>      
    */
    if (IsWindows10OrGreater())
    {
        m_osDescribe = "Microsoft Windows 10";
        return m_osDescribe;
    }
    else if (IsWindows8Point1OrGreater()) {
        m_osDescribe = "Microsoft Windows 8.1";
        return m_osDescribe;
    }
    else if (IsWindows8OrGreater()) {
        m_osDescribe = "Microsoft Windows 8";
        return m_osDescribe;
    }


    SYSTEM_INFO info;                //用SYSTEM_INFO结构判断64位AMD处理器
    GetSystemInfo(&info);            //调用GetSystemInfo函数填充结构
    OSVERSIONINFOEX os;
    os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (!GetVersionEx((OSVERSIONINFO*)&os))
    {
        return "false init";
    }

    //下面根据版本信息判断操作系统名称
    switch (os.dwMajorVersion) {                        //判断主版本号
    case 4:
        switch (os.dwMinorVersion) {                //判断次版本号
        case 0:
            if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
                m_osDescribe = "Microsoft Windows NT 4.0";  //1996年7月发布
            else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
                m_osDescribe = "Microsoft Windows 95";
            break;
        case 10:
            m_osDescribe = "Microsoft Windows 98";
            break;
        case 90:
            m_osDescribe = "Microsoft Windows Me";
            break;
        }
        break;
    case 5:
        switch (os.dwMinorVersion) {               //再比较dwMinorVersion的值
        case 0:
            m_osDescribe = "Microsoft Windows 2000";    //1999年12月发布
            break;
        case 1:
            m_osDescribe = "Microsoft Windows XP";      //2001年8月发布
            break;
        case 2:
            if (os.wProductType == VER_NT_WORKSTATION &&
                info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
                m_osDescribe = "Microsoft Windows XP Professional x64 Edition";
            else if (GetSystemMetrics(SM_SERVERR2) == 0)
                m_osDescribe = "Microsoft Windows Server 2003";   //2003年3月发布
            else if (GetSystemMetrics(SM_SERVERR2) != 0)
                m_osDescribe = "Microsoft Windows Server 2003 R2";
            break;
        }
        break;
    case 6:
        switch (os.dwMinorVersion) {
        case 0:
            if (os.wProductType == VER_NT_WORKSTATION)
                m_osDescribe = "Microsoft Windows Vista";
            else
                m_osDescribe = "Microsoft Windows Server 2008";   //服务器版本
            break;
        case 1:
            if (os.wProductType == VER_NT_WORKSTATION)
                m_osDescribe = "Microsoft Windows 7";
            else
                m_osDescribe = "Microsoft Windows Server 2008 R2";
            break;
        case 2:
            m_osDescribe = "Microsoft Windows 7";
            break;
        }
        break;
    default:
        m_osDescribe = "Unknown System";
    }
    return m_osDescribe;
#endif

#ifdef __linux__
    FILE* fp;
    char buffer[100];
    fp = popen("cat /etc/issue", "r");
    fgets(buffer, sizeof(buffer), fp);
    string out = buffer;
    string::size_type posEnd = out.find('\\');
    string osinfo = trim(out.substr(0, posEnd));
    pclose(fp);
    return osinfo;
#endif
}

string SysInfo::sys_static_host_name()
{
#ifdef WIN32
    string machineName;
    TCHAR buf[MAX_COMPUTERNAME_LENGTH + 2];
    DWORD buf_size;
    buf_size = sizeof buf - 1;
    if (GetComputerName(buf, &buf_size)) {
        machineName = buf;
    }
    else {
        machineName = "error hostname";
    }
    return machineName;
#endif // WIN32

#ifdef __linux__
    char name[256];
    gethostname(name, sizeof(name));
    string hostName = name;
    rerturn hostName;
#endif // __linux__


}

double SysInfo::sys_cpu_usage()
{
#ifdef	WIN32
    vector<qulonglong> firstSample = sys.mCpuLoadLastValues;
    vector<qulonglong> secondSample = sys.cpuRawData();
    sys.mCpuLoadLastValues = secondSample;

    qulonglong currentIdle = secondSample[0] - firstSample[0];
    qulonglong currentKernel = secondSample[1] - firstSample[1];
    qulonglong currentUser = secondSample[2] - firstSample[2];
    qulonglong currentSystem = currentKernel + currentUser;

    double percent = (currentSystem - currentIdle) * 100.0 / currentSystem;
    return max(0.0, min(percent, 100.0));
#endif
#ifdef __linux__
    double cpuLoadAverage = cpuLoadAverage();
    //QString load = QString::number(cpuLoadAverage, 10, 2);
    return cpuLoadAverage;
#endif
}

double SysInfo::sys_mem_usage()
{
#ifdef WIN32
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memoryStatus);
    qulonglong memoryPhysicalUsed = memoryStatus.ullTotalPhys - memoryStatus.ullAvailPhys;
    return (double)memoryPhysicalUsed / (double)memoryStatus.ullTotalPhys * 100.0;
#elif __linux__
    double memoryUsed = memoryUsed();
    //QString used = QString::number(memoryUsed, 10, 2);
    return  memoryUsed;
    //return 0;
#endif 
}

double SysInfo::sys_net_usage()
{
    return 55.55;
}



void SysInfo::GetAllAdapterInfo() {
#ifdef WIN32
    int i = 1;
    PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO[ADAPTERNUM];// 10个网卡空间
    unsigned long stSize = sizeof(IP_ADAPTER_INFO) * ADAPTERNUM;
    // 获取所有网卡信息，参数二为输入输出参数 
    int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
    // 空间不足
    if (ERROR_BUFFER_OVERFLOW == nRel) {
        // 释放空间
        if (pIpAdapterInfo != NULL)
            delete[] pIpAdapterInfo;
        return;
    }

    PIP_ADAPTER_INFO cur = pIpAdapterInfo;
    // 多个网卡 通过链表形式链接起来的 
    while (cur) {
        //将网卡描述添加至mac_description
        cards[i - 1].mac_description = cur->Description;

        switch (cur->Type) {
        case MIB_IF_TYPE_OTHER:
            break;
        case MIB_IF_TYPE_ETHERNET:
        {
            IP_ADDR_STRING* pIpAddrString = &(cur->IpAddressList);
            //分别添加IP和子网掩码
            cards[i - 1].ip_address = pIpAddrString->IpAddress.String;
            cards[i - 1].ip_mask = pIpAddrString->IpMask.String;
        }
        break;
        case MIB_IF_TYPE_TOKENRING:
            break;
        case MIB_IF_TYPE_FDDI:
            break;
        case MIB_IF_TYPE_PPP:
            break;
        case MIB_IF_TYPE_LOOPBACK:
            break;
        case MIB_IF_TYPE_SLIP:
            break;
        default://无线网卡,Unknown type
        {
            IP_ADDR_STRING* pIpAddrString = &(cur->IpAddressList);
            //qDebug() << "IP:" << pIpAddrString->IpAddress.String << endl;
            //qDebug() << "子网掩码:" << pIpAddrString->IpMask.String << endl;
            //分别添加IP和子网掩码
            cards[i - 1].ip_address = pIpAddrString->IpAddress.String;
            cards[i - 1].ip_mask = pIpAddrString->IpMask.String;
        }
        break;
        }
        char hex[16] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };

        // mac 地址一般6个字节 
        // mac 二进制转16进制字符串
        char macStr[18] = { 0 };//12+5+1
        int k = 0;
        for (int j = 0; j < cur->AddressLength; j++) {
            macStr[k++] = hex[(cur->Address[j] & 0xf0) >> 4];
            macStr[k++] = hex[cur->Address[j] & 0x0f];
            macStr[k++] = '-';
        }
        macStr[k - 1] = 0;
        cards[i - 1].mac_address = macStr;

        //qDebug() << "MAC:" << macStr << endl; // mac地址 16进制字符串表示 
        cur = cur->Next;
        //qDebug() << "--------------------------------------------------" << endl;

        //添加到qmap中，i++
        string name = "Card" + i;
        auto pr = std::make_pair(name, cards[i - 1]);
        net_card_info_.insert(pr);
        i++;
    }

    // 释放空间
    if (pIpAdapterInfo != NULL)
        delete[] pIpAdapterInfo;

#endif
#ifdef __linux__
    int  k = 0;
    int fd;
    int interfaceNum = 0;
    struct ifreq buf[16];
    struct ifconf ifc;
    struct ifreq ifrcopy;
    char mac[16] = { 0 };
    char ip[32] = { 0 };
    char broadAddr[32] = { 0 };
    char subnetMask[32] = { 0 };

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");

        close(fd);
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = (caddr_t)buf;
    if (!ioctl(fd, SIOCGIFCONF, (char*)&ifc))
    {
        interfaceNum = ifc.ifc_len / sizeof(struct ifreq);
        //printf("interface num = %d\n", interfaceNum);
        while (interfaceNum-- > 0)
        {
            cards[k].mac_description = buf[interfaceNum].ifr_name;

            //排除未工作接口  
            ifrcopy = buf[interfaceNum];
            if (ioctl(fd, SIOCGIFFLAGS, &ifrcopy))
            {
                printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
                close(fd);
            }

            //获取mac地址
            if (!ioctl(fd, SIOCGIFHWADDR, (char*)(&buf[interfaceNum])))
            {
                memset(mac, 0, sizeof(mac));
                snprintf(mac, sizeof(mac), "%02x%02x%02x%02x%02x%02x",
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[0],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[1],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[2],

                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[3],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[4],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[5]);
                cards[k].mac_address = mac;
                //printf("device mac: %s\n", mac);
            }
            else
            {
                printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
                close(fd);
            }

            //获取ip地址
            if (!ioctl(fd, SIOCGIFADDR, (char*)&buf[interfaceNum]))
            {
                snprintf(ip, sizeof(ip), "%s",
                    (char*)inet_ntoa(((struct sockaddr_in*)&(buf[interfaceNum].ifr_addr))->sin_addr));
                cards[k].ip_address = ip;
                //printf("device ip: %s\n", ip);
            }
            else
            {
                printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
                close(fd);
            }

            //获取子网掩码
            if (!ioctl(fd, SIOCGIFNETMASK, &buf[interfaceNum]))
            {
                snprintf(subnetMask, sizeof(subnetMask), "%s",
                    (char*)inet_ntoa(((struct sockaddr_in*)&(buf[interfaceNum].ifr_netmask))->sin_addr));
                cards[k].ip_mask = subnetMask;
                //printf("device subnetMask: %s\n", subnetMask);
            }
            else
            {
                printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
                close(fd);
            }
            string name = "Card" + (k + 1);
            net_card_info_.insert(name, cards[k]);
            k++;
        }
    }
    else
    {
        printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
        close(fd);
    }
    close(fd);
#endif
}

void SysInfo::GetSpeed(string netcardname) {
    //创建查询表
#ifdef WIN32
    HQUERY query;
    PDH_STATUS status = PdhOpenQuery(NULL, NULL, &query);

    if (status != ERROR_SUCCESS)
        std::cout << "Open Query Error" << std::endl;

    //创建2个计数器
    HCOUNTER hcsend_speed;
    HCOUNTER hcresv_speed;
    hcsend_speed = (HCOUNTER*)GlobalAlloc(GPTR, sizeof(HCOUNTER));
    hcresv_speed = (HCOUNTER*)GlobalAlloc(GPTR, sizeof(HCOUNTER));

    //将()替换为[]
    std::string net_card_name = netcardname;
    replace_all_distinct(net_card_name, "(", "[");
    replace_all_distinct(net_card_name, ")", "]");
    std::string input_send = "\\Network Interface(" + net_card_name + ")\\Bytes Sent/sec";
    std::string input_recv = "\\Network Interface(" + net_card_name + ")\\Bytes Received/sec";


    //添加计数器内容 双引号内容可以从perfmon.msc里面添加后右键属性查看
    status = PdhAddCounter(query, LPCSTR(input_send.c_str()), NULL, &hcsend_speed);
    if (status != ERROR_SUCCESS)
    {
        return;
    }
    status = PdhAddCounter(query, LPCSTR(input_recv.c_str()), NULL, &hcresv_speed);
    if (status != ERROR_SUCCESS)
    {
        return;
    }

    if (status != ERROR_SUCCESS)
        cout << "Add Counter Error" << endl;

    PdhCollectQueryData(query);

    Sleep(1000);

    PdhCollectQueryData(query);

    PDH_FMT_COUNTERVALUE pdhValue;
    DWORD dwValue;

    status = PdhGetFormattedCounterValue(hcresv_speed, PDH_FMT_DOUBLE, &dwValue, &pdhValue);
    if (status != ERROR_SUCCESS) {
        cout << "Netcard path error" << endl;
    }
    resv_speed_ = pdhValue.doubleValue / 1024;


    status = PdhGetFormattedCounterValue(hcsend_speed, PDH_FMT_DOUBLE, &dwValue, &pdhValue);
    if (status != ERROR_SUCCESS) {
        cout << "Get Value Error" << endl;
    }
    send_speed_ = pdhValue.doubleValue / 1024;

    PdhCloseQuery(query);
#endif

#ifdef __linux__
    //初始化
    if (count == 1) {
        net_previous_timeStamp_ = net_current_timeStamp_ = time(NULL);
        net_dif_time_ = 0;
        resv_total_pre_ = resv_total_;
        send_total_pre_ = send_total_;
        resv_speed_ = 0;
        send_speed_ = 0;
    }
    else {
        net_current_timeStamp_ = time(NULL);
        net_dif_time_ = (double)(net_current_timeStamp_ - net_previous_timeStamp_);
        if ((net_dif_time_) >= NET_DIFF_TIME) {//只有满足达到时间戳以后，才更新接收与发送的网络字节数据信息   
            resv_speed_ = (resv_total_ - resv_total_pre_) / NET_DIFF_TIME * 1024;//更新接收网速(单位：KB/s)
            send_speed_ = (send_total_ - send_total_pre_) / NET_DIFF_TIME * 1024;//更新发送网速(单位：KB/s)
            //test
            // qDebug() << "resv_total_:"<<resv_total_<<endl;
            // qDebug() << "resv_total_pre_:"<<resv_total_pre_<<endl;
            // qDebug() << "resv_speed_:"<<resv_speed_<<endl;
            // qDebug() << "send_speed_:"<<send_speed_<<endl;
            //更新
            net_previous_timeStamp_ = net_current_timeStamp_;
            resv_total_pre_ = resv_total_;
            send_total_pre_ = send_total_;
        }
    }
    count++;
#endif
}

void SysInfo::GetSysNetworkFlow() {
#ifdef WIN32
    resv_total_ = send_total_ = 0;
    //创建MIB_IFTABLE
    MIB_IFTABLE* pMibIfTable;
    pMibIfTable = (MIB_IFTABLE*)malloc(sizeof(MIB_IFTABLE));
    //设置缓存区大小
    ULONG dwBufferLen = sizeof(MIB_IFTABLE);
    //获取MIB_II接口表
    DWORD dwRet = GetIfTable(pMibIfTable, &dwBufferLen, TRUE);

    //根据实际表大小进行分配
    if (ERROR_INSUFFICIENT_BUFFER == dwRet)
    {
        free(pMibIfTable);
        pMibIfTable = (MIB_IFTABLE*)malloc(dwBufferLen);
    }
    //重新获取接口表
    dwRet = GetIfTable(pMibIfTable, &dwBufferLen, TRUE);
    if (NO_ERROR != dwRet)
    {
        std::cout << "GetIfTable != NO_ERROR, ErrorCode=" << dwRet << std::endl;
        free(pMibIfTable);
        return;
    }

    //遍历网卡获取流量
    for (int i = 0; i < (pMibIfTable->dwNumEntries); ++i)
    {
        if (pMibIfTable->table[i].dwType <= 23)
        {
            resv_total_ += pMibIfTable->table[i].dwInOctets;
            send_total_ += pMibIfTable->table[i].dwOutOctets;
        }
    }

    resv_total_ = resv_total_ / 1024 / 1024;
    send_total_ = send_total_ / 1024 / 1024;

    free(pMibIfTable);
#endif

#ifdef __linux__
    std::string net_card_name = fReturnNetcardName().toStdString();
    if (net_card_name.empty())
        return;

    ifstream fin("/proc/net/dev");
    if (!fin.is_open())
        return;

    // 跳过头两行
    std::string line;
    getline(fin, line);
    getline(fin, line);

    if (!fin.good())
        return;

    // 从设备中查找
    while (fin.good())
    {
        getline(fin, line);
        if (line.empty())
            continue;

        string::size_type posEnd = line.find(':');
        if (posEnd == string::npos)
            continue;

        string interfaceName = trim(line.substr(0, posEnd));
        if (interfaceName.empty())
            continue;

        // 和需要监控的网卡名进行对比
        if (net_card_name != interfaceName)
            continue;

        // 获取数据
        unsigned long long bytesIn = 0;
        unsigned long long packetsIn = 5;
        unsigned long long errorsIn = 0;
        unsigned long long dropsIn = 0;
        unsigned long long bytesOut = 0;
        unsigned long long packetsOut = 0;
        unsigned long long errorsOut = 0;
        unsigned long long dropsOut = 0;
        unsigned long long dummy = 0;

        istringstream sin(trim(line.substr(posEnd + 1)));

        sin >> bytesIn
            >> packetsIn
            >> errorsIn
            >> dropsIn
            >> dummy
            >> dummy
            >> dummy
            >> dummy
            >> bytesOut
            >> packetsOut
            >> errorsOut
            >> dropsOut;

        if (sin.fail())
            break;

        resv_total_ = bytesIn / 1024 / 1024;
        send_total_ = bytesOut / 1024 / 1024;
        //qDebug() << resv_total_ << endl;
        //qDebug() << send_total_ << endl;
        break;
    }
#endif
}

int SysInfo::ReturnSendSpeed() {
    return int(SysInfo::send_speed_);
}

int SysInfo::ReturnResvSpeed() {
    return int(SysInfo::resv_speed_);
}

int SysInfo::ReturnSend() {
    return int(SysInfo::send_total_);
}

int SysInfo::ReturnResv() {
    return int(SysInfo::resv_total_);
}

map<string, NetCardInfo> SysInfo::ReturnNetcardInfo() {
    return net_card_info_;
}

string SysInfo::replace_all_distinct(std::string& str, const std::string& old_value, const std::string& new_value) {
    std::string::size_type pos = 0;
    while ((pos = str.find(old_value, pos)) != std::string::npos)
    {
        str = str.replace(pos, old_value.length(), new_value);
        if (new_value.length() > 0)
        {
            pos += new_value.length();
        }
    }
    return str;
}

void SysInfo::Reset() {
    count = 1;
}

SysInfo::SysInfo()
{
    mCpuLoadLastValues.assign(5, 0);
}

SysInfo::~SysInfo()
{
}
