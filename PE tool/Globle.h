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
//��������								
//**************************************************************************								
//ReadPEFile:���ļ���ȡ��������								
//����˵����								
//lpszFile �ļ�·��								
//pFileBuffer ������ָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻�ʵ�ʶ�ȡ�Ĵ�С								
//**************************************************************************								
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer);								
//**************************************************************************								
//CopyFileBufferToImageBuffer:���ļ���FileBuffer���Ƶ�ImageBuffer								
//����˵����								
//pFileBuffer  FileBufferָ��								
//pImageBuffer ImageBufferָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С								
//**************************************************************************								
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer);								
//**************************************************************************								
//CopyImageBufferToNewBuffer:��ImageBuffer�е����ݸ��Ƶ��µĻ�����								
//����˵����								
//pImageBuffer ImageBufferָ��								
//pNewBuffer NewBufferָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С								
//**************************************************************************								
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer);								
//**************************************************************************								
//MemeryTOFile:���ڴ��е����ݸ��Ƶ��ļ�								
//����˵����								
//pMemBuffer �ڴ������ݵ�ָ��								
//size Ҫ���ƵĴ�С								
//lpszFile Ҫ�洢���ļ�·��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С								
//**************************************************************************								
BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile);								
//**************************************************************************								
//RvaToFileOffset:���ڴ�ƫ��ת��Ϊ�ļ�ƫ��								
//����˵����								
//pFileBuffer FileBufferָ��								
//dwRva RVA��ֵ								
//����ֵ˵����								
//����ת�����FOA��ֵ  ���ʧ�ܷ���0								
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


