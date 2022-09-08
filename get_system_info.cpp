#include <iostream> 
#include <string>
#include <string.h>
#include <winsock2.h>//include must before window.h
#include<WS2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>  
#include<array>
#include<vector>
#include<tchar.h>
#include<d3d9.h>
#include <intrin.h>
#include<string>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment (lib,"ws2_32.lib")
#pragma comment(lib, "d3d9.lib")

#pragma warning(disable: 4996)//avoid GetVersionEx to be warned

#define MAX_VALUE_NAME 16383

void QueryKey(HKEY hKey, const TCHAR* targetValue)
{
	DWORD    cValues;   // number of values for key 
	DWORD    retCode;
	TCHAR    pvData[MAX_VALUE_NAME];
	DWORD    cbData = sizeof(TCHAR) * MAX_VALUE_NAME;

	// Get the value count. 
	retCode = RegQueryInfoKey(
		hKey,           // key handle 
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		&cValues,       // number of values for this key 
		NULL,
		NULL,
		NULL,
		NULL);

	// Get the key value. 
	if (cValues)
	{
		retCode = RegGetValue(hKey, NULL, targetValue, RRF_RT_ANY, NULL, pvData, &cbData);
		if (retCode != ERROR_SUCCESS)
		{
			_tprintf(TEXT("RegGetValue fails with error: %d\n", retCode));
			return;
		}
		_tprintf(TEXT("%s: %s\n"), targetValue, pvData);
	}
}

//---- get cpu info ----//
void getCpuInfo()
{
	//1. get cpu name method1: __cpuid
	int cpuInfo[4] = { -1 };
	char cpuManufacture[32] = { 0 };
	char cpuType[32] = { 0 };
	char cpuFreq[32] = { 0 };

	__cpuid(cpuInfo, 0x80000002);
	memcpy(cpuManufacture, cpuInfo, sizeof(cpuInfo));

	__cpuid(cpuInfo, 0x80000003);
	memcpy(cpuType, cpuInfo, sizeof(cpuInfo));

	__cpuid(cpuInfo, 0x80000004);
	memcpy(cpuFreq, cpuInfo, sizeof(cpuInfo));

	std::cout << "name: " << cpuManufacture << cpuType << cpuFreq << std::endl;

	//get cpu name methond2: Registry
	HKEY hKey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"),
		0,
		KEY_READ,
		&hKey) == ERROR_SUCCESS)
	{
		QueryKey(hKey, L"ProcessorNameString");
	}
	RegCloseKey(hKey);

	//2. get cpu ProcessorId
	std::array<int, 4> cpui;
	// Calling __cpuid with 0x0 as the function_id argument  
	// gets the number of the highest valid function ID.
	__cpuid(cpui.data(), 0x0);    //cpui[0] = "funcition_id的最大值"
	int nIds_ = cpui[0];
	std::vector<std::array<int, 4>> data_;  //保存遍历到的所有cpui的值    
	for (int i = 0; i <= nIds_; ++i)
	{
		__cpuidex(cpui.data(), i, 0);
		data_.push_back(cpui);
	}
	//reinterpret_cast<int*>(vendor) //*reinterpret_cast<int*>(vendor)
	//索引0 0+4 0+8的值构成了CPU芯片的名称
	char vendor[0x20] = { 0 };
	*reinterpret_cast<int*>(vendor) = data_[0][1];
	*reinterpret_cast<int*>(vendor + 4) = data_[0][3];
	*reinterpret_cast<int*>(vendor + 8) = data_[0][2];  // vendor="GenuineIntel"    
	std::string vendor_ = vendor;
	bool isIntel_ = false;
	bool isAMD = false;
	if ("GenuineIntel" == vendor_)
	{
		isIntel_ = true;    //厂商为INTEL
	}
	else if ("AuthenticAMD" == vendor_)
	{
		isAMD = true;       //厂商为AMD
	}
	char vendorSerialNumber[0x14] = { 0 };
	sprintf_s(vendorSerialNumber, sizeof(vendorSerialNumber), "%08X%08X", data_[1][3], data_[1][0]);  
	std::cout << "ProcessorId: " << vendorSerialNumber << std::endl;

	//3. get cpu NumberOfLogicalProcessors
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	std::cout << "NumberOfLogicalProcessors: " << si.dwNumberOfProcessors << std::endl;

	//4. get cpu NumberOfCores
	PSYSTEM_LOGICAL_PROCESSOR_INFORMATION pBuffer = NULL;
	DWORD dwSize = 0;

	BOOL bResult = GetLogicalProcessorInformation(pBuffer, &dwSize);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		_tprintf(TEXT("Impossible to get processor information\n"));
		return;
	}

	//获得SYSTEM_LOGICAL_PROCESSOR_INFORMATION数组，数组中包含了所有逻辑处理器信息
	pBuffer = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION)malloc(dwSize);
	bResult = GetLogicalProcessorInformation(pBuffer, &dwSize);
	if (!bResult) {
		free(pBuffer);
		_tprintf(TEXT("Impossible to get processor information\n"));
		return;
	}

	DWORD procCoreCount = 0;
	//逻辑处理器数量
	DWORD lpiCount = dwSize / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
	for (DWORD current = 0; current < lpiCount; current++) {
		//逻辑处理器的Relationship为RelationProcessorCore，表示该逻辑处理器是处理器核心
		if (pBuffer[current].Relationship == RelationProcessorCore) {
			procCoreCount++;
		}
	}

	std::cout << "NumberOfCores: " << procCoreCount << std::endl;

	free(pBuffer);
}

//----get board info----//
void getBoardInfo() 
{
	HKEY hKey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("HARDWARE\\DESCRIPTION\\System\\BIOS"),
		0,
		KEY_READ,
		&hKey) == ERROR_SUCCESS)
	{
		QueryKey(hKey, L"BaseBoardManufacturer");
		QueryKey(hKey, L"BaseBoardProduct");
	}
	RegCloseKey(hKey);
}

//---- get memory info ----//
typedef struct _dmi_header
{
	BYTE type;
	BYTE length;
	WORD handle;
}dmi_header;

typedef struct _RawSMBIOSData
{
	BYTE    Used20CallingMethod;
	BYTE    SMBIOSMajorVersion;
	BYTE    SMBIOSMinorVersion;
	BYTE    DmiRevision;
	DWORD   Length;
	BYTE    SMBIOSTableData[];
}RawSMBIOSData;

const char* dmi_string(const dmi_header* dm, BYTE s)
{
	char* bp = (char*)dm;
	size_t i, len;

	if (s == 0)
		return "Not Specified";

	bp += dm->length;
	while (s > 1 && *bp)
	{
		bp += strlen(bp);
		bp++;
		s--;
	}

	if (!*bp)
		return "BAD_INDEX";

	/* ASCII filtering */
	len = strlen(bp);
	for (i = 0; i < len; i++)
		if (bp[i] < 32 || bp[i] == 127)
			bp[i] = '.';

	return bp;
}

void getMemoryInfo()
{
	int ret = 0;
	RawSMBIOSData* smbios;
	dmi_header* h = NULL;

	ret = GetSystemFirmwareTable('RSMB', 0, 0, 0);
	if (!ret)
	{
		printf("GetSystemFirmwareTable Function failed!\n");
		return;
	}

	//printf("get buffer size is %d\n", ret);
	DWORD bufSize = ret;
	char* buf = new char[bufSize];
	memset(buf, 0, bufSize);

	ret = GetSystemFirmwareTable('RSMB', 0, buf, bufSize);
	if (!ret)
	{
		printf("GetSystemFirmwareTable Function failed!\n");
		delete[]buf;
		return;
	}

	//以下为解析smbios数据（好像不太稳定）
	smbios = (RawSMBIOSData*)buf;

	BYTE* p = smbios->SMBIOSTableData;

	if (smbios->Length != bufSize - 8)
	{
		printf("smbios length error\n");
		delete[]buf;
		return;
	}
	
	BYTE* lastAddress = p + smbios->Length;

	int num = 0;
	/*while(true)
	{
		h = (dmi_header*)p;

		if ((h->type == 127) && (h->length == 4))
			break;

		if (h->type == 17) {
			if (p[0xc] + p[0xd] * 0x100 == 0)
				continue;
			printf("memory %d\n", ++num);
			printf("Capacity: %d MB\n", p[0xc] + p[0xd] * 0x100);
			printf("Speed: %dMHz\n", p[0x15] + p[0x16] * 0x100);
			printf("Manufacturer: %s\n", dmi_string(h, p[0x17]));			
		}

		p += h->length;
		while (0 != (*p | *(p + 1))) p++;
		p += 2;

		if (p >= lastAddress) break;
	}*/

	for (int i = 0; i < smbios->Length; i++) {
		h = (dmi_header*)p;

		if (h->type == 17) {
			if (p[0xc] + p[0xd] * 0x100 == 0)
				continue;
			printf("memory %d\n", ++num);
			printf("Capacity: %d MB\n", p[0xc] + p[0xd] * 0x100);
			printf("Speed: %dMHz\n", p[0x15] + p[0x16] * 0x100);
			printf("Manufacturer: %s\n", dmi_string(h, p[0x17]));
		}

		p += h->length;
		while ((*(WORD*)p) != 0) p++;
		p += 2;
	}

	delete[]buf;
	return;
}

//---- get disk info ----//
void getDiskInfo() {
	HKEY hTestKey;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("HARDWARE\\DEVICEMAP\\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"),
		0,
		KEY_READ,
		&hTestKey) == ERROR_SUCCESS
		)
	{
		QueryKey(hTestKey,L"Identifier");
		QueryKey(hTestKey, L"SerialNumber");
	}

	RegCloseKey(hTestKey);

	//通过GetLogicalDriveStrings()函数获取所有驱动器字符串信息长度  
	int dsLength = GetLogicalDriveStringsA(0, NULL);

	CHAR* dStr = new CHAR[dsLength];
	memset(dStr, 0, dsLength);

	//通过GetLogicalDriveStrings将字符串信息复制到堆区数组中,其中保存了所有驱动器的信息。  
	GetLogicalDriveStringsA(dsLength, dStr);

	unsigned _int64 tmpBytes;
	unsigned _int64 fixedTotalBytes = 0; //本地磁盘
	//unsigned _int64 remoteTotalBytes = 0; //网络磁盘
	//unsigned _int64 removableTotalBytes = 0;

	//读取各驱动器信息，由于dStr内部数据格式是A:\NULLB:\NULLC:\NULL，所以dsLength/4可以获得具体大循环范围  
	for (int i = 0; i < dsLength / 4; ++i)
	{
		CHAR* strDriver = dStr + i * 4;
		//std::cout << strDriver << std::endl;

		BOOL fResult = GetDiskFreeSpaceExA(strDriver, NULL, (PULARGE_INTEGER)&tmpBytes, NULL);
		if (fResult)
		{
			int dType = GetDriveTypeA(strDriver);
			if (dType == DRIVE_FIXED)
			{
				fixedTotalBytes += tmpBytes;
			}
			/*switch (dType)
			{
			case DRIVE_FIXED:
				fixedTotalBytes += tmpBytes;
				break;
			case DRIVE_REMOTE:
				remoteTotalBytes += tmpBytes;
				break;
			default:
				break;
			}*/
		}
	}

	std::cout << "Local Disk Size：" << fixedTotalBytes << std::endl;
	//std::cout << "NetWork Disk Size：" << remoteTotalBytes << std::endl;
}

//---- get network info ----//
void getNetWorkinfo() {
	PIP_ADAPTER_ADDRESSES  pIpAdapterAddresses = NULL;
	ULONG outBufLen = 0;
	char buff[100];
	DWORD buffLen = 100;

	int ret = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pIpAdapterAddresses, &outBufLen);
	if (ret == ERROR_BUFFER_OVERFLOW) {
		pIpAdapterAddresses = (PIP_ADAPTER_ADDRESSES)new BYTE[outBufLen];
		ret = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pIpAdapterAddresses, &outBufLen);
	}

	if (ret == ERROR_SUCCESS) {
		int cardIndex = 0;

		while (pIpAdapterAddresses) {
			std::cout << "NetWorkCard" << ++cardIndex << std::endl;

			char buf[BUFSIZ];
			memset(buf, 0, BUFSIZ);
			WideCharToMultiByte(CP_ACP, 0, pIpAdapterAddresses->Description, wcslen(pIpAdapterAddresses->Description), buf, BUFSIZ, NULL, NULL);
			printf("Description: %s\n", buf);

			printf("MACAddress : %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",
				pIpAdapterAddresses->PhysicalAddress[0], pIpAdapterAddresses->PhysicalAddress[1],
				pIpAdapterAddresses->PhysicalAddress[2], pIpAdapterAddresses->PhysicalAddress[3],
				pIpAdapterAddresses->PhysicalAddress[4], pIpAdapterAddresses->PhysicalAddress[5]);
		
			PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pIpAdapterAddresses->FirstUnicastAddress;

			int i = 0;
			for (; pUnicast != NULL; i++) {

				if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
					sockaddr_in* sa_in = (sockaddr_in*)pUnicast->Address.lpSockaddr;
					printf("IPV4 Unicast Address:%s\n", inet_ntop(AF_INET, &(sa_in->sin_addr), buff, buffLen));

				}
				else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
					sockaddr_in6* sa_in6 = (sockaddr_in6*)pUnicast->Address.lpSockaddr;
					printf("IPV6:%s\n", inet_ntop(AF_INET6, &(sa_in6->sin6_addr), buff, buffLen));

				}
				else {
					printf("\tUNSPEC");
				}

				pUnicast = pUnicast->Next;
			}

			//printf("Number of Unicast Addresses: %d\n", i);
			pIpAdapterAddresses = pIpAdapterAddresses->Next;
		}
	}

	if (pIpAdapterAddresses)
		delete[] pIpAdapterAddresses;
}

//----- get video info ------//
//void DumpVideo(DISPLAY_DEVICE& dd)
//{
//	//std::cout << dd.DeviceName << std::endl;
//	char buf[BUFSIZ];
//	memset(buf, 0, BUFSIZ);
//	WideCharToMultiByte(CP_ACP, 0, dd.DeviceString, wcslen(dd.DeviceString), buf, BUFSIZ, NULL, NULL);
//	printf("Description: %s\n", buf);
//}

void getVideoInfo() 
{ 
	LPDIRECT3D9 pD3D = NULL;
	pD3D = Direct3DCreate9(D3D_SDK_VERSION);//创建Direct 3D对象
	DWORD adapterNumber = pD3D->GetAdapterCount();//获得显卡数量
	std::cout << "number of video card: " << adapterNumber << std::endl;
	for (UINT iAdapter = 0; iAdapter < adapterNumber; iAdapter++)
	{
		D3DADAPTER_IDENTIFIER9 di;
		pD3D->GetAdapterIdentifier(iAdapter, 0, &di);//获得显卡信息
		std::cout << "Caption: " << di.Description << std::endl;
	}

	/*DISPLAY_DEVICE displayDevice;
	displayDevice.cb = sizeof(DISPLAY_DEVICE);
	DWORD videoNum = 0;
	while (EnumDisplayDevices(NULL, videoNum, &displayDevice, 0)) {
		DumpVideo(displayDevice);
		videoNum++;
	}*/
}

int main(int argc, char* argv[])
{
	std::cout << "=== cpu infomation ===" << std::endl;
	getCpuInfo();
	std::cout << std::endl;

	std::cout << "=== board infomation ===" << std::endl;
	getBoardInfo();
	std::cout << std::endl;

	std::cout << "=== memory information ===" << std::endl;
	getMemoryInfo();
	std::cout << std::endl;

	std::cout << "=== disk information ===" << std::endl;
	getDiskInfo();
	std::cout << std::endl;

	std::cout << "=== network information ===" << std::endl;
	getNetWorkinfo();
	std::cout << std::endl;

	std::cout << "=== video information ===" << std::endl;
	getVideoInfo();
	std::cout << std::endl;

	system("pause");
	return 0;
}