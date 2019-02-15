#include "Globle.h"


DWORD FileSize;
#define  WhoIsBigger(a,b)  a>b?a:b;
#define WhoIsSmall(a,b) a<b?a:b
BYTE    NewSectionName[IMAGE_SIZEOF_SHORT_NAME] = {0X4C,0X71,0X59,0X00,0x00,0x00,0x00,0x00};
BYTE SHELLCODE[]={

	0X6A,0X00,0X6A,0X00,0X6A,0X00,0X6A,0X00,
	0XE8,0X00,0X00,0X00,0X00,
	0XE9,0X00,0X00,0X00,0X00
};
VOID PrintResource()
{
	PVOID PFileBuffer=NULL;
	PVOID PNewBuffer = NULL;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;	
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_RESOURCE_DIRECTORY pResourceDiretory = NULL,pResourceDiretory1=NULL,pResourceDiretory2=NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry = NULL,pResourceEntry1=NULL,pResourceEntry2=NULL;
	PIMAGE_RESOURCE_DIR_STRING_U pstr =NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory =NULL;
	FileSize = ReadPEFile(ipmsg_url1,&PFileBuffer);
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PFileBuffer);
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("Not a PE file");
		free(PFileBuffer);
		return ;
	}
	pNTHeader = PIMAGE_NT_HEADERS((DWORD)PFileBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("Not a  PE file");
		free(PFileBuffer);
		return;
	}	
	
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	//找到资源表第一层入口
	pResourceDiretory =  PIMAGE_RESOURCE_DIRECTORY ((DWORD)PFileBuffer+RVA_TO_FAV(pOptionHeader->DataDirectory[2].VirtualAddress,PFileBuffer));
	DWORD sourcenum = pResourceDiretory->NumberOfIdEntries+pResourceDiretory->NumberOfNamedEntries;
	DWORD sourcenum1  =0,sourcenum2=0;
	pResourceEntry= PIMAGE_RESOURCE_DIRECTORY_ENTRY ((DWORD)(pResourceDiretory+1));
	
	for(int i=0;i<sourcenum;i++)
	{		
		//遍历资源的类型
		if(pResourceEntry[i].NameIsString)
		{
	
			pstr= (PIMAGE_RESOURCE_DIR_STRING_U)pResourceEntry[i].NameOffset;
			printf("资源类型名称:\n");
			for(int j=0;j<pstr->Length;j++)
				printf("%c",*(pstr->NameString+j));
			printf("\n");
			printf("---------------\n");
		}
		else
		{
			printf("资源类型ID:%d\n",pResourceEntry[i].Id);	
			printf("---------------\n");
		}
			//遍历某类型资源			
		if(pResourceEntry[i].DataIsDirectory)
		{
			//下一层目录的起始位置
			pResourceDiretory1 = PIMAGE_RESOURCE_DIRECTORY	(pResourceEntry[i].OffsetToDirectory+(DWORD)pResourceDiretory);
			sourcenum1 = pResourceDiretory1->NumberOfIdEntries+pResourceDiretory1->NumberOfNamedEntries;
			pResourceEntry1= PIMAGE_RESOURCE_DIRECTORY_ENTRY ((DWORD)(pResourceDiretory1+1));
			for(int j=0;j<sourcenum1;j++)
			{
				if(pResourceEntry[j].NameIsString)
				{	
					pstr= (PIMAGE_RESOURCE_DIR_STRING_U)pResourceEntry1[j].NameOffset;
					printf("此类型资源名称:\n");
					for(int j=0;j<pstr->Length;j++)
						printf("%c",*(pstr->NameString+j));
					printf("\n");
				}
				else
				{

					printf("此类型资源编号ID:%d\n",pResourceEntry1[j].Id);	
				}
				if(pResourceEntry1[j].DataIsDirectory)
				{
					pResourceDiretory2 = PIMAGE_RESOURCE_DIRECTORY (pResourceEntry1[j].OffsetToDirectory+(DWORD)pResourceDiretory);
					pResourceEntry2= PIMAGE_RESOURCE_DIRECTORY_ENTRY ((DWORD)(pResourceDiretory2+1));
					sourcenum2 = pResourceDiretory2->NumberOfIdEntries+pResourceDiretory2->NumberOfNamedEntries;
					printf("此类型资源数量:%d\n",sourcenum2);	
					printf("代码页:%d\n",pResourceEntry2->Id);
					if(!pResourceEntry2->DataIsDirectory)
					{
						pDataDirectory = PIMAGE_DATA_DIRECTORY (pResourceEntry2->OffsetToDirectory+(DWORD)pResourceDiretory);					 
						printf("RVA:%x\n",pDataDirectory->VirtualAddress);
						printf("size:%x\n",pDataDirectory->Size);	
					}
				}
			
			}

		}
	}
}
VOID Movereloct()
{
	AddSection();
	PVOID PFileBuffer=NULL;
	PVOID PNewBuffer = NULL;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;	
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_BASE_RELOCATION pRelocation=NULL;
	PIMAGE_SECTION_HEADER	LpSectionHeader=NULL;
	FileSize = ReadPEFile(url,&PFileBuffer);
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PFileBuffer);
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("Not a PE file");
		free(PFileBuffer);
		return ;
	}
	pNTHeader = PIMAGE_NT_HEADERS((DWORD)PFileBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("Not a  PE file");
		free(PFileBuffer);
		return;
	}	
	
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = PIMAGE_SECTION_HEADER((DWORD)pOptionHeader+pFILEHeader->SizeOfOptionalHeader);
	LpSectionHeader= PIMAGE_SECTION_HEADER(pSectionHeader+pFILEHeader->NumberOfSections-1);
	pRelocation =PIMAGE_BASE_RELOCATION ((DWORD)PFileBuffer+ RVA_TO_FAV(pOptionHeader->DataDirectory[5].VirtualAddress,PFileBuffer));
	for(INT len =0;pRelocation->VirtualAddress!=0;pRelocation=PIMAGE_BASE_RELOCATION ((DWORD)pRelocation+pRelocation->SizeOfBlock))
	{
		
		memcpy((void*)(len+LpSectionHeader->PointerToRawData+(DWORD)PFileBuffer),(void*)pRelocation,pRelocation->SizeOfBlock);
		len += pRelocation->SizeOfBlock;
		
	}
	//修改表位置
	
	pOptionHeader->DataDirectory[5].VirtualAddress = FAV_TO_RVA(LpSectionHeader->PointerToRawData,PFileBuffer);
	MemeryTOFile(PFileBuffer,FileSize,url_r);
	free(PFileBuffer);
		
	
}
VOID MoveExport()
{
	AddSection();
	PVOID PFileBuffer=NULL;
	PVOID PNewBuffer = NULL;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;	
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory=NULL;
	FileSize = ReadPEFile(url,&PFileBuffer);
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PFileBuffer);
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("Not a PE file");
		free(PFileBuffer);
		return ;
	}
	pNTHeader = PIMAGE_NT_HEADERS((DWORD)PFileBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("Not a  PE file");
		free(PFileBuffer);
		return;
	}	
	
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = PIMAGE_SECTION_HEADER((DWORD)pOptionHeader+pFILEHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER LastpSectionHeader = pSectionHeader+pFILEHeader->NumberOfSections-1;
	pExportDirectory = PIMAGE_EXPORT_DIRECTORY ((DWORD)PFileBuffer+RVA_TO_FAV(pOptionHeader->DataDirectory[0].VirtualAddress,PFileBuffer));
	//新增节表开始地址
	DWORD cpybase = (DWORD)PFileBuffer+LastpSectionHeader->PointerToRawData;
	//函数表实际开始地址
	//561068
	DWORD funcbase= (DWORD)PFileBuffer+RVA_TO_FAV(pExportDirectory->AddressOfFunctions,PFileBuffer);
    //55ae10
	//序号表实际开始地址
	DWORD namebase  = (DWORD)PFileBuffer+RVA_TO_FAV(pExportDirectory->AddressOfNames,PFileBuffer);
	//名字表实际开始地址  //55ae24
	DWORD ordinalbase = (DWORD)PFileBuffer+RVA_TO_FAV(pExportDirectory->AddressOfNameOrdinals,PFileBuffer);
	//55ae30
	//移动函数地址表 序号表   名字表
	memcpy((void*)cpybase,(void*)(funcbase),pExportDirectory->NumberOfFunctions*4);
	memcpy((void*)(cpybase+pExportDirectory->NumberOfFunctions*4),(void*)(ordinalbase),pExportDirectory->NumberOfNames*2);
	memcpy((void*)(cpybase+pExportDirectory->NumberOfFunctions*4+pExportDirectory->NumberOfNames*2),
		(void*)(namebase),pExportDirectory->NumberOfNames*4);
	//新的三个表的表头地址
	DWORD newfuncbase  = cpybase;
	DWORD newordinalbase= cpybase+pExportDirectory->NumberOfFunctions*4;
	DWORD newnamebase = cpybase+pExportDirectory->NumberOfFunctions*4+pExportDirectory->NumberOfNames*2;
	//将名字移动到三个表尾处
	DWORD str=0;
	int len =0;
	DWORD strbase = cpybase+pExportDirectory->NumberOfFunctions*4+pExportDirectory->NumberOfNames*6;
	for(int i=0;i<pExportDirectory->NumberOfNames;i++)
	{
		
		str = RVA_TO_FAV(*((PDWORD)namebase+i),PFileBuffer)+(DWORD)PFileBuffer;
		strcpy((char*)(strbase+len),(char*)str);
		//修改名字表和名字地址表的关系
		*((PDWORD)newnamebase+i)=FAV_TO_RVA(strbase+len-(DWORD)PFileBuffer,PFileBuffer);
		len += strlen((char*)str);
		len++;

	}
	//结构体移动地址
	DWORD newexportbase = strbase+len;
	//修改结构体
	pExportDirectory->AddressOfNames =  FAV_TO_RVA(newnamebase-(DWORD)PFileBuffer,PFileBuffer);
	pExportDirectory->AddressOfFunctions = FAV_TO_RVA(newfuncbase-(DWORD)PFileBuffer,PFileBuffer);
	pExportDirectory->AddressOfNameOrdinals =FAV_TO_RVA(newordinalbase-(DWORD)PFileBuffer,PFileBuffer);
	
	//移动结构体
	memcpy((void*)newexportbase,(void*)pExportDirectory,sizeof(*(pExportDirectory)));
	
	pOptionHeader->DataDirectory[0].VirtualAddress = FAV_TO_RVA(newexportbase-(DWORD)PFileBuffer,PFileBuffer);							
	//存
	MemeryTOFile(PFileBuffer,FileSize,url_n);
	free(PFileBuffer);

}
VOID DLLInject()
{	
	AddSection();
	PVOID PFileBuffer=NULL;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_IMPORT_DESCRIPTOR  pImportDirectory=NULL;
	PIMAGE_SECTION_HEADER  pSectionHeader=NULL;
	PIMAGE_SECTION_HEADER LpSectionHeader=NULL;
	FileSize = ReadPEFile(url,&PFileBuffer);
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PFileBuffer);
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("Not a PE file");
		free(PFileBuffer);
		return ;
	}
	pNTHeader = PIMAGE_NT_HEADERS((DWORD)PFileBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("Not a  PE file");
		free(PFileBuffer);
		return;
	}		
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader  =PIMAGE_SECTION_HEADER ((DWORD)pOptionHeader+pFILEHeader->SizeOfOptionalHeader);
	LpSectionHeader =PIMAGE_SECTION_HEADER(pSectionHeader+pFILEHeader->NumberOfSections-1);
	pImportDirectory = PIMAGE_IMPORT_DESCRIPTOR (RVA_TO_FAV(pOptionHeader->DataDirectory[1].VirtualAddress,PFileBuffer)+(DWORD)PFileBuffer);
	PIMAGE_IMPORT_DESCRIPTOR newdirectory = NULL;
	DWORD copybegin = (DWORD)PFileBuffer+LpSectionHeader->PointerToRawData;
	//移动导入表
	while(!((pImportDirectory->FirstThunk==0)&&(pImportDirectory->OriginalFirstThunk==0)))
	{
		memcpy((void*)copybegin,pImportDirectory,sizeof(*pImportDirectory));	
		copybegin+=sizeof(*pImportDirectory);
		pImportDirectory++;
	}
	
	//新增导入表
	
	DWORD newint = copybegin+2*sizeof(*pImportDirectory);
	DWORD niat =newint+0x08;
	PIMAGE_IMPORT_BY_NAME nnametable = PIMAGE_IMPORT_BY_NAME (niat+0x08);
	DWORD  dllname = (DWORD)(nnametable->Name) +strlen(Func_Name)+1;
	nnametable->Hint = 0;
	strcpy((char*)(nnametable->Name),Func_Name);
	strcpy((char*)dllname,Dll_Name);
	*((PDWORD)newint) =  FAV_TO_RVA((DWORD)nnametable-(DWORD)PFileBuffer,PFileBuffer);
	*(PDWORD)niat =  *((PDWORD)newint);
	pImportDirectory = PIMAGE_IMPORT_DESCRIPTOR (copybegin) ; 
	pImportDirectory->OriginalFirstThunk =  FAV_TO_RVA(newint-(DWORD)PFileBuffer,PFileBuffer);
	pImportDirectory->FirstThunk  = FAV_TO_RVA	(niat-(DWORD)PFileBuffer,PFileBuffer);
	pImportDirectory->Name = FAV_TO_RVA(dllname-(DWORD)PFileBuffer,PFileBuffer);
	//总大小是
	//修改原表目录
	pOptionHeader->DataDirectory[1].VirtualAddress = FAV_TO_RVA(LpSectionHeader->PointerToRawData,PFileBuffer);
	pOptionHeader->DataDirectory[1].Size += 20;	
	
	MemeryTOFile(PFileBuffer,FileSize,ipmsg_url1); 
	free(PFileBuffer);
}
VOID PrintBoundImport()
{
	PVOID PFileBuffer=NULL;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundimport=NULL;
	FileSize = ReadPEFile(Notepad_Url,&PFileBuffer);
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PFileBuffer);
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("Not a PE file");
		free(PFileBuffer);
		return;
	} 
	pNTHeader = PIMAGE_NT_HEADERS((DWORD)PFileBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("Not a  PE file");
		free(PFileBuffer);
		return;
	}	
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pBoundimport = PIMAGE_BOUND_IMPORT_DESCRIPTOR(RVA_TO_FAV(pOptionHeader->DataDirectory[11].VirtualAddress,PFileBuffer)+(DWORD)PFileBuffer);
	DWORD descriptor =(DWORD) pBoundimport;
	while(!(pBoundimport->TimeDateStamp==0&&pBoundimport->NumberOfModuleForwarderRefs==0))
	{
		
		printf("%x---%s\n",pBoundimport->TimeDateStamp,descriptor+pBoundimport->OffsetModuleName);
		pBoundimport  = pBoundimport+1+pBoundimport->NumberOfModuleForwarderRefs;
	}
	
	
}
VOID PrintRelocation()
{
	PVOID PFileBuffer=NULL;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_BASE_RELOCATION pRelocation=NULL;
	FileSize = ReadPEFile(DLL_Url,&PFileBuffer);
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PFileBuffer);
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("Not a PE file");
		free(PFileBuffer);
		return ;
	}
	pNTHeader = PIMAGE_NT_HEADERS((DWORD)PFileBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("Not a  PE file");
		free(PFileBuffer);
		return;
	}	
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pRelocation= PIMAGE_BASE_RELOCATION  ((DWORD)PFileBuffer+RVA_TO_FAV(pOptionHeader->DataDirectory[5].VirtualAddress,PFileBuffer));
	INT	i=0;	
	DWORD tmp=0;
	while(pRelocation->VirtualAddress!=0)
	{	
		printf("------RVA--%x---\n",pRelocation->VirtualAddress);
		for(i=0;i<(pRelocation->SizeOfBlock-8)/2;i++)
		{
			tmp	=*((PWORD)(pRelocation+1)+i);			
			printf("RVA :%x   offset:%x type:%x\n",pRelocation->VirtualAddress+(tmp&0X0FFF),RVA_TO_FAV((tmp&0X0FFF)+pRelocation->VirtualAddress,PFileBuffer),tmp>>12);
		}
		printf("-----------------\n");
		pRelocation = PIMAGE_BASE_RELOCATION ((DWORD)pRelocation+pRelocation->SizeOfBlock);
	}

}
VOID Printimport()
{
	PVOID PFileBuffer=NULL;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_IMPORT_DESCRIPTOR  pImportDirectory=NULL;
	FileSize = ReadPEFile(ipmsg_url,&PFileBuffer);
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PFileBuffer);
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("Not a PE file");
		free(PFileBuffer);
		return ;
	}
	pNTHeader = PIMAGE_NT_HEADERS((DWORD)PFileBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("Not a  PE file");
		free(PFileBuffer);
		return;
	}	
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32 ((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pImportDirectory =PIMAGE_IMPORT_DESCRIPTOR ((DWORD)PFileBuffer+RVA_TO_FAV(pOptionHeader->DataDirectory[1].VirtualAddress,PFileBuffer));
	PDWORD pa =NULL;	
	PIMAGE_IMPORT_BY_NAME pimagename =NULL;
	while(!(pImportDirectory->FirstThunk==0&&pImportDirectory->OriginalFirstThunk==0))
	{
		printf ("use the moudle: %s\n",(DWORD)PFileBuffer+RVA_TO_FAV(pImportDirectory->Name,PFileBuffer));
		pa =(PDWORD)(RVA_TO_FAV(pImportDirectory->OriginalFirstThunk,PFileBuffer)+(DWORD)PFileBuffer);
		while(*(pa)!=0)
		{
			
			if( *pa & IMAGE_ORDINAL_FLAG32)
			{
				printf("use the function by ordinal :%x\n",(*pa)&0x7fffffff);
			}
			else
			{					
				pimagename = PIMAGE_IMPORT_BY_NAME (RVA_TO_FAV((DWORD)(*pa),PFileBuffer)+(DWORD)PFileBuffer);
				printf("use the function by name :%s\n",pimagename->Name);
			}
			pa++;
		}		
		pImportDirectory =PIMAGE_IMPORT_DESCRIPTOR (pImportDirectory+1);
	}
}
VOID PrintExport()
{
	PVOID PFileBuffer=NULL;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory=NULL;
	FileSize = ReadPEFile(DLL_Url,&PFileBuffer);
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PFileBuffer);
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("Not a PE file");
		free(PFileBuffer);
		return ;
	}
	pNTHeader = PIMAGE_NT_HEADERS((DWORD)PFileBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("Not a  PE file");
		free(PFileBuffer);
		return;
	}	
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	Tableprint("导出表",pOptionHeader->DataDirectory[0],PFileBuffer);
    pExportDirectory= PIMAGE_EXPORT_DIRECTORY  ((DWORD)PFileBuffer+RVA_TO_FAV(pOptionHeader->DataDirectory[0].VirtualAddress,PFileBuffer));
	printf("%x\n",RVA_TO_FAV(pExportDirectory->AddressOfFunctions,PFileBuffer));
	printf("%x\n",RVA_TO_FAV(pExportDirectory->AddressOfNameOrdinals,PFileBuffer));
	printf("%x\n",RVA_TO_FAV(pExportDirectory->AddressOfNames,PFileBuffer));
	printf("%x\n",pExportDirectory->Base);
	printf("%x\n",pExportDirectory->Characteristics);
	printf("%x\n",pExportDirectory->MajorVersion);
	printf("%x\n",pExportDirectory->MinorVersion);
	printf("%x\n",RVA_TO_FAV(pExportDirectory->Name,PFileBuffer));
	printf("%x\n",pExportDirectory->NumberOfFunctions);
	printf("%x\n",pExportDirectory->NumberOfNames);
	printf("%x\n",pExportDirectory->TimeDateStamp);
    
	
	printf("导出表文件名字:%s\n",(DWORD)PFileBuffer+RVA_TO_FAV(pExportDirectory->Name,PFileBuffer));
	for(int i=0;i<pExportDirectory->NumberOfFunctions;i++)
	{
		printf("函数地址:%x\n",*((PDWORD)((DWORD)PFileBuffer+RVA_TO_FAV(pExportDirectory->AddressOfFunctions,PFileBuffer))+i));
		
	}
	for(i=0;i<pExportDirectory->NumberOfNames;i++)
	{
		printf("函数名:%s\n",(DWORD)PFileBuffer+RVA_TO_FAV(*((PDWORD)((DWORD)PFileBuffer+RVA_TO_FAV(pExportDirectory->AddressOfNames,PFileBuffer))+i),PFileBuffer));
		
	}

	for(i=0;i<pExportDirectory->NumberOfNames;i++)
	{
		printf("函数序号:%x\n",*((PWORD)((DWORD)PFileBuffer+RVA_TO_FAV(pExportDirectory->AddressOfNameOrdinals,PFileBuffer))+i)+pExportDirectory->Base);
		
	}
	free(PFileBuffer);
}
VOID GetFunctionAddressByName()
{

	PVOID pFileBuffer =NULL;
	LPSTR fname = "Div";
	PVOID PFileBuffer=NULL;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;	
	PIMAGE_DATA_DIRECTORY  pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory=NULL;
	FileSize = ReadPEFile(DLL_Url,&PFileBuffer);
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PFileBuffer);
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("Not a PE file");
		free(pFileBuffer);
		return ;
	}
	pNTHeader = PIMAGE_NT_HEADERS((DWORD)PFileBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("Not a  PE file");
		free(pFileBuffer);
		return;
	}	
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);

    
	pExportDirectory= PIMAGE_EXPORT_DIRECTORY  ((DWORD)PFileBuffer+RVA_TO_FAV(pOptionHeader->DataDirectory[0].VirtualAddress,PFileBuffer));
	for(int i=0;i<pExportDirectory->NumberOfNames;i++)
	{
		if(strcmp(fname,(CHAR*)((DWORD)PFileBuffer+RVA_TO_FAV(*((PDWORD)((DWORD)PFileBuffer+
			RVA_TO_FAV(pExportDirectory->AddressOfNames,PFileBuffer))+i),PFileBuffer)))==0)
			break;
	}
	if(i==pExportDirectory->NumberOfNames)
	{
		printf("find fname fail");
		free(PFileBuffer);
		return ;
	}
	
	i = *((PWORD)((DWORD)PFileBuffer+RVA_TO_FAV(pExportDirectory->AddressOfNameOrdinals,PFileBuffer))+i);
	printf("%s的函数地址是:%x",fname,*((PDWORD)((DWORD)PFileBuffer+RVA_TO_FAV(pExportDirectory->AddressOfFunctions,PFileBuffer))+i));
	
	free(pFileBuffer);
	return;

}
VOID GetFunctionAddressByOrdinal()
{
	PVOID PFileBuffer=NULL;
	WORD Ordinal=0x0d;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_DATA_DIRECTORY  pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory=NULL;
	FileSize = ReadPEFile(DLL_Url,&PFileBuffer);
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PFileBuffer);
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("Not a PE file");
		free(PFileBuffer);
		return ;
	}
	pNTHeader = PIMAGE_NT_HEADERS((DWORD)PFileBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("Not a  PE file");
		free(PFileBuffer);
		return;
	}	
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
    pExportDirectory= PIMAGE_EXPORT_DIRECTORY  ((DWORD)PFileBuffer+RVA_TO_FAV(pOptionHeader->DataDirectory[0].VirtualAddress,PFileBuffer));
	SHORT Ord =  Ordinal-pExportDirectory->Base;
	if(Ord<0||Ord>pExportDirectory->NumberOfFunctions)
	{
		printf("fail");
		return;
	}
	printf("%d号的函数地址是:%x",Ordinal,*((PDWORD)((DWORD)PFileBuffer+RVA_TO_FAV(pExportDirectory->AddressOfFunctions,PFileBuffer))+Ord));
	free(PFileBuffer);
}
VOID PrintTable()
{
	
	PVOID PFileBuffer=NULL;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;	
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_DATA_DIRECTORY  pDataDirectory = NULL;
	FileSize = ReadPEFile(Notepad_Url,&PFileBuffer);
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PFileBuffer);
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("Not a PE file");
		free(PFileBuffer);
		return ;
	}
	pNTHeader = PIMAGE_NT_HEADERS((DWORD)PFileBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("Not a  PE file");
		free(PFileBuffer);
		return;
	}	
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	
	
	Tableprint("导出表",pOptionHeader->DataDirectory[0],PFileBuffer);
	
	Tableprint("导入表",pOptionHeader->DataDirectory[1],PFileBuffer);
	Tableprint("资源",pOptionHeader->DataDirectory[2],PFileBuffer);
	Tableprint("异常",pOptionHeader->DataDirectory[3],PFileBuffer);
	Tableprint("安全证书",pOptionHeader->DataDirectory[4],PFileBuffer);
	Tableprint("重定位表",pOptionHeader->DataDirectory[5],PFileBuffer);
	Tableprint("调试信息",pOptionHeader->DataDirectory[6],PFileBuffer);
	Tableprint("版权所有",pOptionHeader->DataDirectory[7],PFileBuffer);
	Tableprint("全局指针",pOptionHeader->DataDirectory[8],PFileBuffer);
	Tableprint("TSL表",pOptionHeader->DataDirectory[9],PFileBuffer);
	Tableprint("加载配置表",pOptionHeader->DataDirectory[10],PFileBuffer);
	Tableprint("绑定导入",pOptionHeader->DataDirectory[11],PFileBuffer);
	Tableprint("TAT表",pOptionHeader->DataDirectory[12],PFileBuffer);
	Tableprint("延迟导入",pOptionHeader->DataDirectory[13],PFileBuffer);
	Tableprint("COM",pOptionHeader->DataDirectory[14],PFileBuffer);
	Tableprint("留言",pOptionHeader->DataDirectory[15],PFileBuffer);
    
	free(PFileBuffer);
	 


}
VOID Tableprint(LPSTR ptr, IMAGE_DATA_DIRECTORY TABLE,PVOID pFilebuffer)
{
	printf("------%s-------\n",ptr);
	printf("%x\n",TABLE.VirtualAddress);
	printf("%x\n",TABLE.Size);
	printf("-------------------\n");
} 
DWORD RVA_TO_FAV(DWORD RVA,PVOID PFileBuffer)
{
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_SECTION_HEADER   pSectionHeader = NULL;
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PFileBuffer);
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("Not a PE file");
		return -1;
	}
	pNTHeader = PIMAGE_NT_HEADERS((DWORD)PFileBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("Not a  PE file");
		return -1;
	}	
	pFILEHeader=PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader =PIMAGE_SECTION_HEADER((DWORD)pOptionHeader+pFILEHeader->SizeOfOptionalHeader);
	
	if(RVA>pOptionHeader->SizeOfImage)
	{
		return -1;
	}
	INT i=0;
	while((RVA>=(pSectionHeader+i)->VirtualAddress)&&i<pFILEHeader->NumberOfSections){i++;}
	i--;
	if(i<0)
	{
		if(RVA>pOptionHeader->SizeOfHeaders||RVA<0)
			return -1;
		else
			return RVA;
	}
	if(RVA-(pSectionHeader+i)->VirtualAddress>(pSectionHeader+i)->SizeOfRawData)
		return -1;
	
	return RVA-(pSectionHeader+i)->VirtualAddress+(pSectionHeader+i)->PointerToRawData;
	
}

DWORD FAV_TO_RVA(DWORD FVA,PVOID PFileBuffer)
{
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_SECTION_HEADER   pSectionHeader = NULL;
	PIMAGE_SECTION_HEADER lpSectionHeader=NULL;
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PFileBuffer);
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("Not a PE file");
		return -1;
	}
	pNTHeader = PIMAGE_NT_HEADERS((DWORD)PFileBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("Not a  PE file");
		return -1;
	}	
	pFILEHeader=PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader=PIMAGE_SECTION_HEADER((DWORD)pOptionHeader+pFILEHeader->SizeOfOptionalHeader);
	lpSectionHeader= PIMAGE_SECTION_HEADER(pSectionHeader+pFILEHeader->NumberOfSections-1);
	if(FVA<0||FVA>(lpSectionHeader->PointerToRawData+lpSectionHeader->SizeOfRawData))
	{
		printf("translate fail");
		return -1;
	}
	INT i=0;
	while(FVA>=(pSectionHeader+i)->PointerToRawData&&i<pFILEHeader->NumberOfSections){i++;}
	i--;
	if(i<0)
	{
		return FVA;
	}

	return FVA-(pSectionHeader+i)->PointerToRawData+(pSectionHeader+i)->VirtualAddress;
}
VOID MergeSection()
{ 	
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_SECTION_HEADER  pSectionHeader =NULL;
	PIMAGE_SECTION_HEADER LastpSectionHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PVOID PFileBuffer=NULL;
	PVOID PImageBuffer=NULL;
	PVOID PNewBuffer=NULL;

	FileSize = ReadPEFile(DLL_Url,&PFileBuffer);
	
	CopyFileBufferToImageBuffer(PFileBuffer,&PImageBuffer);
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PImageBuffer);
	pNTHeader = PIMAGE_NT_HEADERS ((DWORD)PImageBuffer+pDOSHeader->e_lfanew);
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = PIMAGE_SECTION_HEADER((DWORD)pOptionHeader+pFILEHeader->SizeOfOptionalHeader);
	LastpSectionHeader  =  PIMAGE_SECTION_HEADER(pSectionHeader+pFILEHeader->NumberOfSections-1);
	DWORD size = WhoIsBigger(LastpSectionHeader->Misc.VirtualSize,LastpSectionHeader->SizeOfRawData);
	//修改 表数 
	DWORD X;
	for(int i=0;i<pFILEHeader->NumberOfSections;i++)
	{
		X|=(pSectionHeader+i)->Characteristics;
	}
	pSectionHeader->Characteristics=X;
	pSectionHeader->Misc.VirtualSize= LastpSectionHeader->VirtualAddress+size-pSectionHeader->VirtualAddress;
	pSectionHeader->SizeOfRawData = pSectionHeader->Misc.VirtualSize;
	pFILEHeader->NumberOfSections=1;
	
	CopyImageBufferToNewBuffer(PImageBuffer,&PNewBuffer);
	
	MemeryTOFile(PNewBuffer,FileSize,url);
	
	
}
VOID AddSection()
{
	LPVOID pbuf=NULL;
	DWORD  NTbegin=0;
	DWORD offset =0;
	INT  count=0;
	DWORD size =0;
	DWORD rubbishsize = 0;
	PVOID PFileBuffer=NULL;
	PVOID PImageBuffer=NULL;
	PVOID PNewBuffer=NULL;
	PVOID PExpandBuffer=NULL;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;	
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_SECTION_HEADER  pSectionHeader =NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_SECTION_HEADER NewpSectionHeader =NULL; 
	PIMAGE_SECTION_HEADER LastSectionHeader = NULL;
	FileSize = ReadPEFile(ipmsg_url,&PFileBuffer);
		
	CopyFileBufferToImageBuffer(PFileBuffer,&PImageBuffer);
	
	free(PFileBuffer);
	pDOSHeader =  PIMAGE_DOS_HEADER ((DWORD)PImageBuffer);
	pNTHeader = PIMAGE_NT_HEADERS ((DWORD)PImageBuffer+pDOSHeader->e_lfanew);
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = PIMAGE_SECTION_HEADER((DWORD)pOptionHeader+pFILEHeader->SizeOfOptionalHeader);
	NewpSectionHeader = PIMAGE_SECTION_HEADER (pSectionHeader+pFILEHeader->NumberOfSections);
	LastSectionHeader= PIMAGE_SECTION_HEADER (pSectionHeader+pFILEHeader->NumberOfSections-1);

	offset = WhoIsBigger(LastSectionHeader->Misc.VirtualSize,LastSectionHeader->SizeOfRawData);
	offset= LastSectionHeader->VirtualAddress+offset>pOptionHeader->SizeOfImage?pOptionHeader->SizeOfImage-LastSectionHeader->VirtualAddress:offset;
	while(!(*((PWORD)(NewpSectionHeader+count))))
	{
		count++;
	}
	//判断是否可以再插入一个表
	if(count<0x28)
	{
		count = 0;
		printf("add new section directly fail");
		//开始提升表空间
        
		NTbegin=  (DWORD)(1+&(pDOSHeader->e_lfanew));
		rubbishsize = (DWORD)PImageBuffer+pDOSHeader->e_lfanew - NTbegin;
		DWORD size = ((DWORD)NewpSectionHeader-pDOSHeader->e_lfanew-(DWORD)PImageBuffer);
		memcpy((void*)NTbegin,(void*)pNTHeader,size);	
		memset((void*)((DWORD)NewpSectionHeader-rubbishsize),0,rubbishsize);
		//指针重新赋值
		
		pDOSHeader->e_lfanew = NTbegin-(DWORD) PImageBuffer;
		pNTHeader = PIMAGE_NT_HEADERS ((DWORD)PImageBuffer+pDOSHeader->e_lfanew);
		pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
		pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
		pSectionHeader = PIMAGE_SECTION_HEADER((DWORD)pOptionHeader+pFILEHeader->SizeOfOptionalHeader);
		NewpSectionHeader = PIMAGE_SECTION_HEADER (pSectionHeader+pFILEHeader->NumberOfSections);
		LastSectionHeader= PIMAGE_SECTION_HEADER (pSectionHeader+pFILEHeader->NumberOfSections-1);
		//判断是否可以再插入一个表
		while(!(*((PWORD)NewpSectionHeader+count)))
		{
			count++;
		}
		if(count<0x28)
		{
			printf("add new totally fail");

			
			free(PImageBuffer);
			return;
		}
		
	}
	memcpy(NewpSectionHeader,pSectionHeader,0x28);
	//修改NewpSectionHeader中的值
		  
	*((PLONG)NewpSectionHeader->Name)= *((PLONG)NewSectionName);
	NewpSectionHeader->Misc.VirtualSize = Addtionnalsize;
	NewpSectionHeader->VirtualAddress = Align(pOptionHeader->SectionAlignment,LastSectionHeader->VirtualAddress+offset);
	
	NewpSectionHeader->SizeOfRawData =Addtionnalsize;
	NewpSectionHeader->PointerToRawData= LastSectionHeader->PointerToRawData+LastSectionHeader->SizeOfRawData;
	DWORD X=0;
	for(INT i=0;i<pFILEHeader->NumberOfSections;i++)
	{
		X|=(pSectionHeader+i)->Characteristics;
	}
	NewpSectionHeader->Characteristics=X;
	//修改 sizeofimage numberofsection  
	pFILEHeader->NumberOfSections ++ ;
	pOptionHeader->SizeOfImage=Align(pOptionHeader->SectionAlignment,pOptionHeader->SizeOfImage)+Addtionnalsize;
    

	//开始扩大内存
	CopyImageBufferToExpandBuffer(PImageBuffer,&PExpandBuffer);
	
	size= CopyExpandBufferToNewBuffer(PExpandBuffer,&PNewBuffer);

	//恢复文件存盘
	MemeryTOFile(PNewBuffer,size,url);

	free(PNewBuffer);
	free(PExpandBuffer);
	free(PImageBuffer);
	
}
DWORD  Align(DWORD alignment,DWORD num)
{
		
	return num%alignment!=0?alignment*(num/alignment+1):num;
	
}
DWORD CopyImageBufferToExpandBuffer(IN LPVOID pImageBuffer,OUT LPVOID* ExpandBuffer)
{
	LPVOID pBuf=NULL;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_SECTION_HEADER  pSectionHeader =NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	DWORD offset=0;
	if(pImageBuffer==NULL)
	{
		printf("pImageBuffer is empty");
		return 0;
	}
	pDOSHeader = PIMAGE_DOS_HEADER (pImageBuffer);
	
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("not a  PE file");
		return 0;
	}		
	pNTHeader = PIMAGE_NT_HEADERS ((DWORD)pImageBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("not a  PE file");
		return 0;

	}		
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader=PIMAGE_SECTION_HEADER((DWORD)pOptionHeader+pFILEHeader->SizeOfOptionalHeader);

	pBuf = malloc(pOptionHeader->SizeOfImage);
	memset(pBuf,0,pOptionHeader->SizeOfImage);
	memcpy((void*)pBuf,(void*)pImageBuffer,pOptionHeader->SizeOfImage-Addtionnalsize);
	*ExpandBuffer = pBuf;
	pBuf =NULL;
	return pOptionHeader->SizeOfImage;
  
}

BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile)
{
		FILE *fp;
		if((fp=fopen(lpszFile,"ab+"))==NULL)
		{
			printf("write file fail");
			return 0;
		}
		DWORD n=fwrite(pMemBuffer,sizeof(char),size,fp);
		fclose(fp);
		return n;

}
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer)
{
		LPVOID pBuf;
		PIMAGE_DOS_HEADER pDOSHeader=NULL;
		PIMAGE_FILE_HEADER pFILEHeader=NULL;
		PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
		PIMAGE_SECTION_HEADER  pSectionHeader =NULL;
		PIMAGE_NT_HEADERS pNTHeader=NULL;
		DWORD	offset = 0;
		if(pImageBuffer==NULL)
		{
			printf("error");
			return 0;
		}
		pDOSHeader = PIMAGE_DOS_HEADER (pImageBuffer);
		
		if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
		{
			printf("error");
			return 0;
		}		
		pNTHeader  = PIMAGE_NT_HEADERS ((DWORD)pImageBuffer+pDOSHeader->e_lfanew);
		if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
		{
			printf("not a  PE file");
			return 0;
		}		
		pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
		pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
		pSectionHeader=PIMAGE_SECTION_HEADER((DWORD)pOptionHeader+pFILEHeader->SizeOfOptionalHeader);
		FileSize = pOptionHeader->SizeOfHeaders+pSectionHeader->SizeOfRawData;
	    pBuf =malloc(FileSize);
		memset(pBuf,0,FileSize);
		
		memcpy(pBuf,pImageBuffer,pOptionHeader->SizeOfHeaders);
		
		for(int i=0;i<pFILEHeader->NumberOfSections-1;i++,pSectionHeader++)
		{

			memcpy((void*)((DWORD)pBuf+pSectionHeader->PointerToRawData),(void*)((DWORD)pImageBuffer+pSectionHeader->VirtualAddress),pSectionHeader->SizeOfRawData);
		}
		//防越界判断 
		offset=	pSectionHeader->VirtualAddress+pSectionHeader->SizeOfRawData>pOptionHeader->SizeOfImage	?pSectionHeader->Misc.VirtualSize:pSectionHeader->SizeOfRawData;
		memcpy((void*)(pSectionHeader->VirtualAddress+(DWORD)pBuf),(void*)(pSectionHeader->PointerToRawData+(DWORD)pImageBuffer),offset);
		*pNewBuffer	=pBuf;
		pBuf=NULL;
		return  pOptionHeader->SizeOfImage;

}

DWORD CopyExpandBufferToNewBuffer(IN LPVOID pExpandBuffer,OUT LPVOID* pNewBuffer)
{
	LPVOID pBuf;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_SECTION_HEADER  pSectionHeader =NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	DWORD offset=0;
	
	if(pExpandBuffer==NULL)
	{
		printf("error");
		return 0;
	}
	pDOSHeader = PIMAGE_DOS_HEADER (pExpandBuffer);
	
	if(*((PWORD)pDOSHeader)!=IMAGE_DOS_SIGNATURE)
	{
		printf("error");
		return 0;
	}		
	pNTHeader  = PIMAGE_NT_HEADERS ((DWORD)pExpandBuffer+pDOSHeader->e_lfanew);
	if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
	{
		printf("not a  PE file");
		return 0;
	}		
	pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)pNTHeader+4);
	pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader=PIMAGE_SECTION_HEADER((DWORD)pOptionHeader+pFILEHeader->SizeOfOptionalHeader);
	
	pBuf =malloc(FileSize+Addtionnalsize);
	memset(pBuf,0,FileSize+Addtionnalsize);
	
	memcpy(pBuf,pExpandBuffer,pOptionHeader->SizeOfHeaders);
	
	for(int i=0;i<pFILEHeader->NumberOfSections;i++,pSectionHeader++)
	{
		//防越界判断 
		offset=	pSectionHeader->VirtualAddress+pSectionHeader->SizeOfRawData>(pOptionHeader->SizeOfImage-Addtionnalsize)?pSectionHeader->Misc.VirtualSize:pSectionHeader->SizeOfRawData;
		memcpy((void*)((DWORD)pBuf+pSectionHeader->PointerToRawData),(void*)((DWORD)pExpandBuffer+pSectionHeader->VirtualAddress),offset);
	}
	
	*pNewBuffer	=pBuf;
	pBuf=NULL;
	return  FileSize+Addtionnalsize;
	
}
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer)
{
		
		LPVOID pBuf=NULL;
		PIMAGE_DOS_HEADER pDOSHeader=NULL;
		PIMAGE_FILE_HEADER pFILEHeader=NULL;
		PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
		PIMAGE_SECTION_HEADER  pSectionHeader =NULL;
		PIMAGE_NT_HEADERS pNTHeader=NULL;
		DWORD offset = 0;
		if(pFileBuffer==NULL)
		{
			printf("error");
			return 0;
		}
		if(*((PWORD)pFileBuffer)!=IMAGE_DOS_SIGNATURE)
		{
			printf("error");
			return 0;
		}
		pDOSHeader=PIMAGE_DOS_HEADER (pFileBuffer);
		pNTHeader = PIMAGE_NT_HEADERS ((DWORD)pFileBuffer+pDOSHeader->e_lfanew);	
		if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
		{
			printf("not a  PE file");
			return 0;
		}
			
		pFILEHeader = PIMAGE_FILE_HEADER ((DWORD)(pNTHeader)+4);
		pOptionHeader = PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
		pSectionHeader =PIMAGE_SECTION_HEADER((DWORD)pOptionHeader+pFILEHeader->SizeOfOptionalHeader);
		pBuf = malloc(pOptionHeader->SizeOfImage);		
		if(!pBuf)
		{
			printf("distribute storage fail");
			return 0;
		}
		memset(pBuf,0,pOptionHeader->SizeOfImage);
		memcpy(pBuf,pFileBuffer,pOptionHeader->SizeOfHeaders);		
		for(int i=0;i<pFILEHeader->NumberOfSections-1;i++,pSectionHeader++)
		{
			memcpy((void*)(pSectionHeader->VirtualAddress+(DWORD)pBuf),(void*)(pSectionHeader->PointerToRawData+(DWORD)pFileBuffer),pSectionHeader->SizeOfRawData);
		}
		//防越界判断 
		offset=	pSectionHeader->VirtualAddress+pSectionHeader->SizeOfRawData>pOptionHeader->SizeOfImage	?pSectionHeader->Misc.VirtualSize:pSectionHeader->SizeOfRawData;
		memcpy((void*)(pSectionHeader->VirtualAddress+(DWORD)pBuf),(void*)(pSectionHeader->PointerToRawData+(DWORD)pFileBuffer),offset);
		*pImageBuffer = pBuf;
		pBuf=NULL;		
		return pOptionHeader->SizeOfImage;
		  
}
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer)
{
		FILE *fp=NULL;
		LPVOID pBUF=NULL;
		DWORD filesize;
		if(!(fp=fopen(lpszFile,"rb")))
		{
			printf("open exe fail");
			return 0;
		}

		fseek(fp,0,SEEK_END);
		filesize = ftell(fp);
		fseek(fp,0,SEEK_SET);
		pBUF = malloc(filesize);
		if(!pBUF)
		{
			printf("distribute storage fail");
			free(pBUF);
			fclose(fp);
			return 0;
		}
		size_t  n  =  fread(pBUF,sizeof(char),filesize,fp);
		if(!n)
		{
			printf("read fail");
			free(pBUF);
			fclose(fp);
			
		}
		*pFileBuffer = pBUF;
		pBUF=NULL;
		fclose(fp);
		return n;			
			
}

VOID AddCodeInCodeArea()
{
	DWORD codebegin=0;
	DWORD calladdr= 0;
	DWORD jmpaddr = 0;
	DWORD size=0;
	BOOL IS_OK= 0;
	BYTE order=1;
	PIMAGE_DOS_HEADER pDOSHeader=NULL;
	PIMAGE_FILE_HEADER pFILEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PVOID PFileBuffer=NULL;
	PVOID PImageBuffer=NULL;
	PVOID PNewBuffer=NULL;
    FileSize=ReadPEFile(Notepad_Url,&PFileBuffer); 
	if(!FileSize)
	{
		printf("Storage-->File Fail");
		free(PFileBuffer);
		return;
	}
	size = CopyFileBufferToImageBuffer(PFileBuffer,&PImageBuffer);
	if(!size)
	{
		printf("File-->image Fail");
		free(PImageBuffer);
		free(PFileBuffer);
		return;
	}
	//判断是否能放下shellcode 

	pDOSHeader =PIMAGE_DOS_HEADER (PImageBuffer);
	pFILEHeader  = PIMAGE_FILE_HEADER((DWORD)PImageBuffer+pDOSHeader->e_lfanew+4);
	pOptionHeader=PIMAGE_OPTIONAL_HEADER32((DWORD)pFILEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader =PIMAGE_SECTION_HEADER((DWORD)pOptionHeader+pFILEHeader->SizeOfOptionalHeader);
	while(((long)(((pSectionHeader+order)->SizeOfRawData)-((pSectionHeader+order)->Misc.VirtualSize))<SIZEOFSHELLCODE)&&(order<pFILEHeader->NumberOfSections))
	{
		printf("the %d section can't involve that code",order+1);
		order++;
	}
	if(order==pFILEHeader->NumberOfSections)
	{
		printf("no spare section");
			return;	
	}
	DWORD X=pSectionHeader->Characteristics;
	DWORD Y=(pSectionHeader+order)->Characteristics;
	(pSectionHeader+order)->Characteristics = X|Y;
	// 放入shellcode
	
	
	codebegin= ((DWORD)PImageBuffer+(pSectionHeader+order)->VirtualAddress+(pSectionHeader+order)->Misc.VirtualSize);
	memcpy((void*)codebegin,(void*)SHELLCODE,SIZEOFSHELLCODE);
	//修正E8 
	calladdr=(((DWORD)PImageBuffer+MessageBoxAddress-pOptionHeader->ImageBase)-(codebegin+0xD));
	*((PDWORD)(codebegin+9))=calladdr;
	//修正E9
	jmpaddr=((DWORD)PImageBuffer+pOptionHeader->AddressOfEntryPoint-(codebegin+SIZEOFSHELLCODE));
	*((PDWORD)(codebegin+14))=jmpaddr;
	//修改OEP
	pOptionHeader->AddressOfEntryPoint=codebegin-(DWORD)PImageBuffer;
	
	
	size = CopyImageBufferToNewBuffer(PImageBuffer,&PNewBuffer);
	if(!size)
	{
		printf("image-->newbuf Fail");
		free(PFileBuffer);
		free(PImageBuffer);
		free(PNewBuffer);
		return;
	}
	IS_OK=MemeryTOFile(PNewBuffer,FileSize,url);
	if(!IS_OK)
	{
		printf("storage fail");
	}
	else
	{
		printf("all the things are ok");
		getchar();
	}
	free(PFileBuffer);
	free(PImageBuffer);
	free(PNewBuffer);
	return;
}
