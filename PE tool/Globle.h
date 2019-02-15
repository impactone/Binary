#include "stdAfx.h"

#define MessageBoxAddress 0X77D507EA
extern DWORD FileSize;
#define  Dll_Name  "1_7_1.dll"
#define  Func_Name "ExportFunction"
#define  Addtionnalsize 0x2000
#define  SIZEOFSHELLCODE  0x12
#define  ipmsg_url   "C://ipmsg.exe"
#define  ipmsg_url1   "C://ipmsg1.exe"
#define  url "C://addsection.exe"
#define  url_r "C://Program Files//moverelocat.dll"
#define  url_n "C://Program Files//moveexport.dll"
#define  Notepad_Url "C://windows//system32//notepad.exe"
#define  Lqy_Url  "C://Program Files//Microsoft Visual Studio//lqy.exe"
#define  DLL_Url  "C:/Program Files/Microsoft Visual Studio/MyProjects/1_5_3/Debug/1_5_3.dll"

extern BYTE SHELLCODE[];
//函数声明								
//**************************************************************************								
//ReadPEFile:将文件读取到缓冲区								
//参数说明：								
//lpszFile 文件路径								
//pFileBuffer 缓冲区指针								
//返回值说明：								
//读取失败返回0  否则返回实际读取的大小								
//**************************************************************************								
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer);								
//**************************************************************************								
//CopyFileBufferToImageBuffer:将文件从FileBuffer复制到ImageBuffer								
//参数说明：								
//pFileBuffer  FileBuffer指针								
//pImageBuffer ImageBuffer指针								
//返回值说明：								
//读取失败返回0  否则返回复制的大小								
//**************************************************************************								
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer);								
//**************************************************************************								
//CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区								
//参数说明：								
//pImageBuffer ImageBuffer指针								
//pNewBuffer NewBuffer指针								
//返回值说明：								
//读取失败返回0  否则返回复制的大小								
//**************************************************************************								
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer);								
//**************************************************************************								
//MemeryTOFile:将内存中的数据复制到文件								
//参数说明：								
//pMemBuffer 内存中数据的指针								
//size 要复制的大小								
//lpszFile 要存储的文件路径								
//返回值说明：								
//读取失败返回0  否则返回复制的大小								
//**************************************************************************								
BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile);								
//**************************************************************************								
//RvaToFileOffset:将内存偏移转换为文件偏移								
//参数说明：								
//pFileBuffer FileBuffer指针								
//dwRva RVA的值								
//返回值说明：								
//返回转换后的FOA的值  如果失败返回0								
//**************************************************************************								
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva);								
DWORD CopyExpandBufferToNewBuffer(IN LPVOID pExpandBuffer,OUT LPVOID* pNewBuffer);
DWORD CopyImageBufferToExpandBuffer(IN LPVOID pImageBuffer,OUT LPVOID* ExpandBuffer);
VOID AddCodeInCodeArea();
VOID AddSection();
VOID MergeSection();
VOID ExpandSection();
VOID PrintTable();
VOID PrintExport();
VOID GetFunctionAddressByName();
VOID GetFunctionAddressByOrdinal();
VOID PrintRelocation();
VOID MoveExport();
VOID Movereloct();
VOID Printimport();
VOID PrintBoundImport();
VOID DLLInject();
VOID PrintResource();
DWORD  Align(DWORD alignment,DWORD num);
DWORD FAV_TO_RVA(DWORD FVA,PVOID PFileBuffer);
DWORD RVA_TO_FAV(DWORD RVA,PVOID PFileBuffer);
VOID Tableprint(LPSTR ptr, IMAGE_DATA_DIRECTORY TABLE,PVOID pFilebuffer);


