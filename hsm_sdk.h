/******************************************************************************************
             Copyright (C), 2015-2020, Joy SRC Elec. Co., Ltd.
 ******************************************************************************************
  Filename   		: 	hsm_sdk.h
  Version    		: 	V0.003
  Function    		: 	hsm sdk header
  History Record	:
  1.Date			: 	2020/09/28
    Author			: 	zhangzhengzheng
    modification   	: 	create
******************************************************************************************/

#ifndef _HSM_SDK_H_
#define _HSM_SDK_H_

/*
 * 头文件
 */
 

//#include "hsm_common.h"

//C++ Start
#ifdef __cplusplus
extern "C" {
#endif





#define SDR_OK 					0 
#define SDR_BASE 				0x1000000 			//错误码基础值
#define SDR_UNKNOWERR 			SDR_BASE+0x00000001 //未知错误
#define SDR_NOTSUPPORT 			SDR_BASE+0x00000002 //不支持的接口调用
#define SDR_COMMFAIL 			SDR_BASE+0x00000003 //与设备通信失败
#define SDR_HARDFAIL 			SDR_BASE+0x00000004 //运算模块元响应
#define SDR_OPENDEVICE 			SDR_BASE+0x00000005 //打开设备失败
#define SDR_OPENSESSION 		SDR_BASE+0x00000006 //创建会话失败
#define SDR_PARDENY 			SDR_BASE+0x00000007 //无私钥使用权限
#define SDR_KEYNOTEXIST 		SDR_BASE+0x00000008 //不存在的密钥调用
#define SDR_ALGNOTSUPPORT 		SDR_BASE+0x00000009 //不支持的算法调用
#define SDR_ALGMODNOTSUPPORT 	SDR_BASE+0x0000000A //不支持的算法模式调用
#define SDR_PKOPERR 			SDR_BASE+0x0000000B //公钥运算失败
#define SDR_SKOPERR 			SDR_BASE+0x0000000C //私钥运算失败
#define SDR_SIGNERR 			SDR_BASE+0x0000000D //签名运算失败
#define SDR_VERIFYERR 			SDR_BASE+0x0000000E //验证签名失败
#define SDR_SYMOPERR 			SDR_BASE+0x0000000F //对称算法运算失败
#define SDR_STEPERR 			SDR_BASE+0x00000010 //多步运算步骤错误
#define SDR_FILESIZEERR 		SDR_BASE+0x00000011 //文件长度超出限制
#define SDR_FILENOEXIST 		SDR_BASE+0x00000012 //指定的文件不存在
#define SDR_FILEOFSERR 			SDR_BASE+0x00000013 //文件起始位置错误
#define SDR_KEYTYPEERR 			SDR_BASE+0x00000014 //密钥类型错误
#define SDR_KEYERR 				SDR_BASE+0x00000015 //密钥错误
#define SDR_ENCDATAERR 			SDR_BASE+0x00000016 //ECC 加密数据错误
#define SDR_RANDERR 			SDR_BASE+0x00000017 //随机数产生失败
#define SDR_PRKRERR 			SDR_BASE+0x00000018 //私钥使用权限获取失败
#define SDR_MACERR 				SDR_BASE+0x00000019 //MAC 运算失败
#define SDR_FILEEXISTS 			SDR_BASE+0x0000001A //指定文件巳存在
#define SDR_FILEWERR 			SDR_BASE+0x0000001B //文件写入失败
#define SDR_NOBUFFER 			SDR_BASE+0x0000001C //存储空间不足
#define SDR_INARGERR 			SDR_BASE+0x0000001D //输人参数错误
#define SDR_OUTARGERR 			SDR_BASE+0x0000001E //输出参数错误
#define	SDR_TASKRUNERR			 SDR_BASE+0x00000020	//一个会话同时调用多个函数
#define	SDR_CARDSTATERR		     SDR_BASE+0x0000009A	//加密卡状态错误（未认证通过、用户权限错误，未进入服务状态）
#define	SDR_START_CONFIG	     SDR_BASE+0x00000022	//启动配置，停止一切密码运算，立马返回
#define SDR_MALLOCERR			 SDR_BASE+0x00000023	//申请内存失败
#define SDR_ACESSPIN_LOCKED			 SDR_BASE+0x00000024	//访问控制码被锁定

#define SDR_TASK_RUNNING		SDR_BASE+0x00000025			//正在运行
#define SDR_RETURN_TASKLENERR	SDR_BASE+0x00000026			//返回任务长度错误
#define SDR_RETURN_TASKTYPEERR	SDR_BASE+0x00000027			//返回任务类型错误
#define SDR_SERIALNUMERR		SDR_BASE+0x00000028			//返回的串号不等
#define SDR_TASKLEN_TOOLONG		SDR_BASE+0x00000029			//任务长度大于通信块大小
#define SDR_WRITE_ASYMKEYERR	SDR_BASE+0x0000002A			//写入非对称密钥失败（密钥索引过大）
#define SDR_WRITE_SYMKEYERR		SDR_BASE+0x0000002B			//写入对称密钥（密钥索引过大）
#define SDR_ERASE_ASYMKEYERR	SDR_BASE+0x0000002C			//擦除非对称密钥失败（密钥索引过大）
#define SDR_ERASE_SYMKEYERR		SDR_BASE+0x0000002D			//擦除对称密钥失败（密钥索引过大）
#define SDR_READ_ASYMKEYERR		SDR_BASE+0x0000002E			//读取非对称密钥失败（密钥索引过大）
#define SDR_READ_SYMKEYERR		SDR_BASE+0x0000002F			//读取对称密钥失败（密钥索引过大）
#define SDR_HASH_CALCERR		SDR_BASE+0x00000030			//hash_calc失败
#define SDR_HASH_COMPAREERR		SDR_BASE+0x00000031			//hash结果对比不一致
#define SDR_HASH_INITERR		SDR_BASE+0x00000032			//Hash_init失败
#define SDR_HASH_UPDATEERR		SDR_BASE+0x00000033			//Hash_updata失败
#define SDR_HASH_ENDERR			SDR_BASE+0x00000034			//Hash_updata失败
#define SDR_READ_IFLASH_4KERR	SDR_BASE+0x00000035			//read_iflash_4k读取失败
#define SDR_READ_FILEERR		SDR_BASE+0x00000036			//读取文件失败
#define SDR_PAGE_EARSEERR		SDR_BASE+0x00000037			//page_earse擦除失败
#define SDR_SM2_KEY_GENERATE	SDR_BASE+0x00000038			//sm2_key_generate生成密钥对失败
#define SDR_WRITE_SESSIONKEYERR	SDR_BASE+0x00000039			//存储会话密钥明文失败
#define SDR_ECCGENERATEKEYERR	SDR_BASE+0x0000003A			//EccGenerateKeyPair ECC生成密钥对失败
#define SDR_SM3_CALS_ZERR		SDR_BASE+0x0000003B			//sm3_calc_z失败
#define SDR_ECC_KEYEXCHANGE_HTERR	SDR_BASE+0x0000003C		//ECC密钥交换失败
#define SDR_ECCDECRYPTERR		SDR_BASE+0x0000003D			//ECCDecrypt ECC加密失败
#define SDR_ECCENCRYPTERR		SDR_BASE+0x0000003E			//ECCEncrypt ECC解密失败
#define SDR_CHANGEPINERR		SDR_BASE+0x0000003F			//Sdf_ChangePIN 更改私钥权限口令失败


/*非对称算法标识定义*/
#if 0
#define SGD_SM2				0x00020000				//SM2椭圆曲线密码算法
#define SGD_SM2_1				0x00020100				//SM2椭圆曲线签名算法
#define SGD_SM2_2				0x00020200				//SM2椭圆曲线密钥交换协议
#define SGD_SM2_3				0x00020400				//SM2椭圆曲线加密算法
#else
#define SGD_RSA                         0x00010000
#define SGD_SM2				0x00020000				//SM2椭圆曲线密码算法
#define SGD_ECC                         0x00020000
#define SGD_SM2_1                       0x00020200
#define SGD_SM2_2                       0x00020400
#define SGD_SM2_3                       0x00020800
#endif



/*对称算法标识定义*/
#define SGD_SM1_ECB   			0x00000101				//SM1算法 ECB加密模式		
#define SGD_SM1_CBC   			0x00000102				//SM1算法 CBC加密模式
#define SGD_SM1_CFB   			0x00000104				//SM1算法 CFB加密模式
#define SGD_SM1_OFB   			0x00000108				//SM1算法 OFB加密模式
#define SGD_SM1_MAC   			0x00000110				//SM1算法 MAC运算
////////////////////SSF33/////////////////
#define SGD_SF33_ECB    		0x00000201				//SSF33算法 ECB加密模式
#define SGD_SF33_CBC    		0x00000202				//SSF33算法 CBC加密模式
#define SGD_SF33_CFB    		0x00000204				//SSF33算法 CFB加密模式
#define SGD_SF33_OFB   		 	0x00000208				//SSF33算法 OFB加密模式
#define SGD_SF33_MAC    		0x00000210				//SSF33算法 MAC运算
////////////////////SM4///////////////////
#define SGD_SM4_ECB   			0x00000401				//SM4算法 ECB加密模式
#define SGD_SM4_CBC   			0x00000402				//SM4算法 CBC加密模式
#define SGD_SM4_CFB   			0x00000404				//SM4算法 CFB加密模式
#define SGD_SM4_OFB   			0x00000408				//SM4算法 OFB加密模式
#define SGD_SM4_MAC   			0x00000410				//SM4算法 MAC运算
////////////////////ZUC///////////////////
#define SGD_ZUC_EEA3   			0x00000801				//ZUC祖冲之机密性算法 128-EEA3算法
#define SGD_ZUC_EIA3   			0x00000802				//ZUC祖冲之完整性算法 128-EIA3算法

/*杂凑类算法标识定义*/
#define	SGD_SM3 				0x00000001				//SM3杂凑算法
#define	SGD_SHA1 				0x00000002				//SHA_1杂凑算法
#define	SGD_SHA256 				0x00000004				//SHA_256杂凑算法



#define ECCref_MAX_BITS 			512
#define ECCref_MAX_LEN  			((ECCref_MAX_BITS+7)/8)




/*ECC公钥结构体*/
typedef struct ECCrefPublicKey_st
{
	unsigned int bits;//密钥模长
	unsigned char x[ECCref_MAX_LEN];//X坐标
	unsigned char y[ECCref_MAX_LEN];//Y坐标
}ECCrefPublicKey;



/*ECC私钥结构体*/
typedef struct ECCrefPrivateKey_st
{
	unsigned int  bits; //密钥模长
	unsigned char K[ECCref_MAX_LEN];//私钥
}ECCrefPrivateKey;

/*ECC签名数据结构体*/
typedef struct ECCSignature_st
{
	unsigned char r[ECCref_MAX_LEN];//签名r部分数据
	unsigned char s[ECCref_MAX_LEN];//签名s部分数据
}ECCSignature;


/*ECC加密数据结构体*/
typedef struct ECCCipher_st
{
	unsigned char x[ECCref_MAX_LEN];//x坐标
	unsigned char y[ECCref_MAX_LEN];//y坐标
	unsigned char M[32];//明文杂凑值
	unsigned int  L;//密文数据长度
	unsigned char C[1];//密文数据
}ECCCipher;


/*设备信息*/
typedef struct DEVICEINFO_st
{
	unsigned char   IssuerName[40]; 		//生产厂商名
	unsigned char   DeviceName[16];			//设备型号
	/*设备串号包含日期（8字符），批次（3字符）流水号（5字符）（不足位时补0）
	例如：20080229-001-00123表示为0x 20 08 02 29 00 10 01 23*/
	unsigned char  	DeviceSerial[16];		
	unsigned int    DeviceVersion;			//密码设备软件版本号
	unsigned int    StandardVersion;		//密码设备支持接口规范版本号
	unsigned int 	AsymAlgAbility[2];		//支持非对称算法
	unsigned int    SymAlgAbility;			//支持对称算法
	unsigned int    HashAlgAbility;			//支持的杂凑算法
	unsigned int    BufferSize;				//支持文件最大存储空间
}
__attribute__ ((packed))
DEVICEINFO;


/*
 * 函数实现
 */


/*=========================================================
Function:SDF_OpenDevice
Description:在所有操作之前要进行打开设备，否则其他进行其他操作。
Args:       [out] phDeviceHandle:设备句柄。
Return:		正确返回SDR_0K，错误返回错误代码返回错误返回错误代码代码。
=========================================================*/
int SDF_OpenDevice(void **phDeviceHandle);

/*========================================================
Function:SDF_CloseSession
Description:在所有操作之后要根据设备句柄关闭相应设备。
Args:		[in] hDeviceHandle：设备句柄。
Return:		正确返回SDR_0K，错误返回错误代码返回错误返回错误代码代码直接跳出。
=========================================================*/
int SDF_CloseDevice(void* hDeviceHandle);

/*=========================================================
Function:SDF_OpenSession
Description:创建与密码设备的会话。
Args:	[in] hDeviceHandle:设备句柄。
		[out] phSessionHandle：会话句柄
Return:	正确返回SDR_0K，错误返回错误代码返回错误返回错误代码代码。
=========================================================*/
int SDF_OpenSession( void* hDeviceHandle,void **phSessionHandle);

/*========================================================
Function:SDF_CloseSession
Description:关闭与密码设备已建立的会话并释放相关资源
Args:	[in] hSessinHandle：会话句柄。
Return:	正确返回SDR_OK，错误返回错误代码返回错误返回错误代码代码。
==========================================================*/
int SDF_CloseSession(void* hSessinHandle);

/*=========================================================
Function:SDF_GetDeviceInfo
Description:
Args:	[in] hSessionHandle:设备句柄；
		[out] pstDeviceInfo:设备信息；
Return:正确返回SDR_OK，错误返回错误代码返回错误返回错误代码代码。
==========================================================*/
int SDF_GetDeviceInfo(void* hSessionHandle,DEVICEINFO*  pstDeviceInfo);

/*=================================================================
Function:SDF_GenerateRandom
Description:调用密码设备产生指定长度到随机数
Args:	[in]	hSessionHandle:设备句柄；
		[in]	uiLength:需要产生随机数的长度；
		[out]	pData:缓冲区指针存放产生的随机数；
Return:正确返回0，错误返回错误代码；
==========================================================*/
int SDF_GenerateRandom(void* hSessionHandle,unsigned int uiLength,unsigned char* pucRandom);

/*=================================================================
Function:SDF_GetPrivateKeyAccessRight
Description:获取密码设备内部存储的指定索引私钥的使用权
Args:	    [in]	hSessionHandle:会话句柄；
			[in]	uiKeyIndex：密码设备存储私钥的索引值		
			[in]    pucPassword：使用私钥权限的标识码
		    [in]    uiPwdLength：私钥访问控制码长度，不少于8字节
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_GetPrivateKeyAccessRight(void* hSessionHandle,unsigned int uiKeyIndex,unsigned char* pucPassword,unsigned int uiPwdLength);

/*=================================================================
Function:SDF_ReleasePrivateKeyAccessRight
Description:释放密码设备内部存储的指定索引私钥的使用权
Args:	[in]	hSessionHandle:会话句柄；
		[in]	uiKeyIndex：密码设备存储私钥的索引值			
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_ReleasePrivateKeyAccessRight(void* hSessionHandle,unsigned int uiKeyIndex);

//对称运算加解密
/*=================================================================================
Function: SDF_Encrypt
Description:使用指定的密钥句柄和IV对数据进行对称加密运算
Args:	[in]	hSessionHandle:会话句柄；
		[in]	phKeyHandle:密钥句柄
		[in]	uiAlgID:算法标识指定对称加密算法
		[in/out]    pucIV:缓冲区指针，用于存放输入和返回的IV数据
		[in]    pucData:缓冲区指针，用于存放输入的数据明文
	    [in]    uiDataLength：输入的数据明文长度
		[out]   pucEncData：缓冲区指针，用于存放输出的数据密文
		[out]   puiEncDataLength：输出的数据密文长度
备注：此函数不对数据进行填充处理，输入的数据必须是指定算法分组长度的整数倍		
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_Encrypt(void  *hSessionHandle,void *phKeyHandle,unsigned int uiAlgID,unsigned char *pucIV,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucEncData,unsigned int *puiEncDatalength);

/*=================================================================================
Function: SDF_Decrypt
Description:使用指定的密钥句柄和IV对数据进行对称解密运算
Args:[in]	hSessionHandle:会话句柄；
	[in]	phKeyHandle:密钥句柄
	[in]	uiAlgID:算法标识指定对称加密算法
	[in/out]    pucIV:缓冲区指针，用于存放输入和返回的IV数据
	[in]    pucData:缓冲区指针，用于存放输入的数据密文
	[in]    uiDataLength：输入的数据密文长度
	[out]   pucEncData：缓冲区指针，用于存放输出的数据明文
	[out]   puiEncDataLength：输出的数据明文长度
备注：此函数不对数据进行填充处理，输入的数据必须是指定算法分组长度的整数倍
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_Decrypt(void *hSessionHandle,void *phKeyHandle,unsigned int uiAlgID,unsigned char *pucIV,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucEncData,unsigned int *puiEncDataLength);

/*=================================================================================
Function: SDF_CalculateMAC
Description:
Args:[in]	hSessionHandle:会话句柄；
	 [in]	phKeyHandle:密钥句柄
	 [in]	uiAlgID:算法标识指定MAC加密算法
	 [in/out]    pucIV:缓冲区指针，用于存放输入和返回的IV数据
	 [in]    pucData:缓冲区指针，用于存放输出的数据明文
	 [in]    uiDataLength：输出的数据明文长度
	 [out]   pucMAC：缓冲区指针，用于存放输出的MAC值
	 [out]   puiMACLength：输出的MAC值长度
备注：此函数不对数据进行分包处理，多包数据MAC运算由IV控制最后的MAC值	
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_CalculateMAC(void  *hSessionHandle,void *phKeyHandle,unsigned int uiAlgID,unsigned char *pucIV,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucMAC,unsigned int *puiMACLength);
//杂凑算法类函数
/*=================================================================================
Function: SDF_HashInit
Description:三步式数据杂凑运算第一步
Args:	[in]	hSessionHandle:会话句柄；
		[in]	uiAlgID：指定杂凑算法标识
	    [in] 	pucPublicKey：签名者公钥，当算法标识为SGD_SM3时有效
		[in]    pucID：签名者ID值，当算法标识为SGD_SM3时有效
	    [in]    uiIDLength：签名者的ID长度，当算法标识为SGD_SM3时有效
备注：uiIDLength长度不为0且	uiAlgID为SGD_SM3时函数执行SM2的预处理1操作	
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_HashInit(void  *hSessionHandle,unsigned int uiAlgID,ECCrefPublicKey *pucPublicKey,unsigned char *pucID,unsigned int uiIDLength);

/*=================================================================================
Function: SDF_HashUpdate
Description:三步式数据杂凑运算第二步，对输入的明文进行杂凑运算
Args:	[in]	hSessionHandle:会话句柄；
		[in]    pucData：缓冲区指针用于存放输入的数据明文
	   [in]    uiDataLength：输入的数据明文长度
Return:正确返回SDR_OK，错误返回错误代码；
=================================================================================*/
int SDF_HashUpdate(void  *hSessionHandle,unsigned char *pucData,unsigned int uiDataLength);

/*=================================================================================
Function: SDF_HashFinal
Description:三步式数据杂凑运算第二步，杂凑运算结束返回杂凑数据并清除中间数据
Args:	[in]	hSessionHandle:会话句柄；
		[out]   pucHash：缓冲区指针，用于存放输出的杂凑数据
	   [out]   uiHashLength：返回的杂凑数据长度
Return:正确返回SDR_OK，错误返回错误代码；
=================================================================================*/
int SDF_HashFinal(void  *hSessionHandle,unsigned char *pucData,unsigned int *puiHashLength);

//文件操作
/*=================================================================================
Function: SDF_CreatFile
Description:在密码设备内部创建用于存储用户数据的文件
Args:	[in]	hSessionHandle:会话句柄；
		[in]    pucFileName：缓冲区指针用于存放输入的文件名，最大长度128字节
	   	[in]    uiNameLen：文件名长度
		[in]    uiFileSize：文件所占存储空间的长度
Return:正确返回SDR_OK，错误返回错误代码；
=================================================================================*/
int SDF_CreateFile(void  *hSessionHandle,unsigned char *pucFileName,unsigned int uiNameLen,unsigned int   uiFileSize);
/*=================================================================================
Function: SDF_ReadFile
Description:读取在密码设备内部存储用户数据的文件内容
Args:	[in]	hSessionHandle:会话句柄；
		[in]    pucFileName：缓冲区指针用于存放输入的文件名，最大长度128字节
	   	[in]    uiNameLen：文件名长度
		[in]    uiOffset：指定读取文件时的偏移值
		[in|out] puiFileLength：入参时指定读取文件内容的长度，出参时返回实际读取文件内容的长度
		[out]   pucbuffer：缓冲区指针，用于存放读取的文件数据
Return:正确返回SDR_OK，错误返回错误代码；
=================================================================================*/
int SDF_ReadFile(void  *hSessionHandle,unsigned char *pucFileName,unsigned int uiNameLen,unsigned int uiOffset, unsigned int  *puiFileLength, unsigned char *pucbuffer);
/*=================================================================================
Function: SDF_WriteFile
Description:向密码设备内部存储用户数据文件中写入内容
Args:	[in]	hSessionHandle:会话句柄；
		[in]    pucFileName：缓冲区指针用于存放输入的文件名，最大长度128字节
	   	[in]    uiNameLen：文件名长度
		[in]    uiOffset：指定写入文件时的偏移值
		[in] puiFileLength指定写入文件内容的长度
		[in]   pucbuffer：缓冲区指针，用于存放输入的写文件数据
Return:正确返回SDR_OK，错误返回错误代码；
=================================================================================*/
int SDF_WriteFile(void  *hSessionHandle,unsigned char *pucFileName,unsigned int uiNameLen,unsigned int uiOffset, unsigned int  uiFileLength, unsigned char *pucbuffer);
/*=================================================================================
Function: SDF_DeleteFile
Description:删除指定文件名的密码设备内部存储用户数据的文件
Args:	[in]	hSessionHandle:会话句柄；
		[in]    pucFileName：缓冲区指针用于存放输入的文件名，最大长度128字节
	   [in]    uiNameLen：文件名长度
Return:正确返回SDR_OK，错误返回错误代码；
=================================================================================*/
int SDF_DeleteFile(void  *hSessionHandle,unsigned char *pucFileName,unsigned int uiNameLen);



//密钥管理类
/*=================================================================
Function:SDF_ExportSignPublicKey_ECC
Description:导出密码设备内部存储的指定索引位置的ECC签名公钥
Args:	[in]	hSessionHandle:会话句柄；
		[in]	uiKeyIndex：密码设备存储的ECC密钥对索引值
		[out] pucPublicKey：ECC公钥结构
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_ExportSignPublicKey_ECC(void *hSessionHandle,unsigned int uiKeyIndex,ECCrefPublicKey *pucPublicKey);
/*=================================================================
Function:SDF_ExportEncPublicKey_ECC
Description:导出密码设备内部存储的指定索引位置的ECC加密公钥
Args:	[in]	hSessionHandle:会话句柄；
		[in]    uiKeyIndex：密码设备存储的ECC密钥对索引值
		[out]   pucPublicKey:ECC公钥结构
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_ExportEncPublicKey_ECC(void *hSessionHandle,unsigned int uiKeyIndex,ECCrefPublicKey *pucPublicKey);
/*=================================================================
Function:SDF_GenerateKeyPair_ECC
Description:请求密码设备产生指定类型的模长的ECC密钥对
Args:	[in]	hSessionHandle:会话句柄；
		[in]    uiAlgID:指定算法标识
		[in]	  uiKeyBits:指定密钥长度
		[out]   pucPublicKey：ECC公钥结构
		[out]   pucPrivateKey：ECC私钥结构
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_GenerateKeyPair_ECC(void *hSessionHandle, unsigned int uiAlgID,unsigned int uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
/*=================================================================
Function: SDF_GenerateKeyWithIPK_ECC
Description:生成会话密钥并用指定索引的内部加密公钥ECC公钥加密输出
Args:	[in]	hSessionHandle:会话句柄；
		[in]    uiIPKIndex：密码设备内部存储公钥的索引值
		[in]	  uiKeyBits：指定产生的会话密钥长度
		[out]  	pucKey：缓冲区指针，用于存放返回的密钥密文
		[out]  	phKeyHandle：返回的密钥句柄
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle,unsigned int uiIPKIndex,unsigned int uiKeyBits,ECCCipher *pucKey,void **phKeyHandle);
/*=================================================================
Function:SDF_GenerateKeyWithEPK_ECC
Description:生成会话密钥并用外部ECC公钥加密输出
Args:	[in]	 hSessionHandle:会话句柄；
		[in]	 uiKeyBits：指定产生的会话密钥长度
		[in]    uiAlgID：外部ECC公钥的算法标识
	   [in]    pucPublicKey：输入的外部ECC公钥结构
		[out]  	pucKey：缓冲区指针，用于存放返回的密钥密文
		[out]	  phKeyHandle：返回的密钥句柄
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle,unsigned int uiKeyBits,unsigned int uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucKey,void **phKeyHandle);
/*=================================================================
Function:SDF_ImportKeyWithISK_ECC
Description:导入会话密钥并用内部ECC私钥解密
Args:	[in]	hSessionHandle:会话句柄；
		[in]	uiISKIndex：密码设备内部存储加密私钥的索引值，对应于加密时的公钥
		[in]   pucKey：缓冲区指针，用于存放返回的密钥密文
		[out]	 phKeyHandle：返回的密钥句柄
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_ImportKeyWithISK_ECC(void *hSessionHandle,unsigned int uiISKIndex,ECCCipher *pucKey,void **phKeyHandle);
/*=================================================================
Function: SDF_GenerateAgreementDataWithECC
Description:使用ECC密钥协商算法，为计算会话密钥而产生协商参数，同时返回指定索引位置的ECC公钥，临时ECC密钥对的
公钥以及协商句柄。
Args:	[in]	hSessionHandle:会话句柄；
[in]	uiISKIndex:密码设备内部存储加密私钥的索引值，该私钥用于密钥协商
[in]    uiKeyBits：要求协商的密钥长度
[in]  	pucSponsorID：参与密钥协商的发起方ID值
[in]   pucSponsorIDLength :参与密钥协商的发起方ID长度
[out]	pucSelfPublicKey：返回的发起方ECC公钥结构
[out]	pucSelfTmpPublicKey：返回的发起方临时ECC公钥结构
[out]	phAgreementHandle：返回的协商密钥句柄，用于计算协商密钥
Return:正确返回SDR_OK，错误返回错误代码；
备注：为协商会话密钥，协商的发起方应首先调用本函数
==========================================================*/
int SDF_GenerateAgreementDataWithECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, void **phAgreementHandle);
/*=================================================================
Function: SDF_GenerateKeyWithECC
Description:使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥，同时返回会话密钥句柄。
Args:	[in]	hSessionHandle:会话句柄；
[in]	pucResponseID:外部输入的响应方ID值
[in]    uiResponseIDLength：外部输入的响应方ID长度
[in]  	pucResponsePublicKey：外部输入的响应方ECC公钥结构
[in]    pucResponseTmpPublicKey :外部输入的响应方临时ECC公钥结构
[in]	phAgreementHandle：协商密钥句柄，用于计算协商密钥
[out]	phKeyHandle：返回的密钥句柄
Return:正确返回SDR_OK，错误返回错误代码；
备注：协商的发起方获得响应方的协商参数后调用本函数，计算会话密钥。使用SM2算法计算会回话密钥的过程见GM/T0009
==========================================================*/
int SDF_GenerateKeyWithECC(void *hSessionHandle, unsigned char *pucResponseID, unsigned int uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey, void *phAgreementHandle, void **phKeyHandle);
/*=================================================================
Function: SDF_GenerateAgreementDataWithECC
Description:使用ECC密钥协商算法，为计算会话密钥而产生协商参数，同时返回指定索引位置的ECC公钥，临时ECC密钥对的
公钥以及协商句柄。
Args:	[in]	hSessionHandle:会话句柄；
[in]	uiISKIndex:密码设备内部存储加密私钥的索引值，该私钥用于密钥协商
[in]    uiKeyBits：协商后要求输出的密钥长度
[in]  	pucResponseID：响应方ID值
[in]    uiResponseIDLength :响应方ID长度
[in]  	pucSponsorID：发起方ID值
[in]    uiSponsorIDLength :发起方ID长度
[in]	pucSponsorPublicKey：外部输入的发起方ECC公钥结构
[in]	pucSponsorTmpPublicKey：外部输入的发起方临时ECC公钥结构
[out]	pucResponsePublicKey：返回的响应方ECC公钥结构
[out]	pucResponseTmpPublicKey：返回的响应方临时ECC公钥结构
[out]	phKeyHandle：返回的密钥句柄
Return:正确返回SDR_OK，错误返回错误代码；
备注：为协商会话密钥，协商的发起方应首先调用本函数
==========================================================*/
int SDF_GenerateAgreementDataAndKeyWithECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucResponseID, unsigned int uiResponseIDLength, unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, void **phKeyHandle);
/*=================================================================
Function: SDF_ExchangeDigitEnvelopeBaseOnECC
Description:将有内部加密公钥加密的会话密钥转换为有外部指定的公钥加密，可用于数字信封装换。
Args:	[in]	hSessionHandle:会话句柄；
[in]	uiKeyIndex:密码设备内部存储密钥加密密钥的索引值
[in]    uiAlgID：外部ECC公钥的算法标识
[in]    pucPublicKey :外部ECC公钥结构
[in]	pucEncDateIn：缓冲区指针，用于存放输入的会话密钥密文
[out]	pucEncDateOut：缓冲区指针，用于存放输出的会话密钥密文
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_ExchangeDigitEnvelopeBaseOnECC(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDateIn, ECCCipher *pucEncDateOut);
/*=================================================================
Function: SDF_GenerateKeyWithKEK
Description:生成会话密钥并用密钥加密密钥输出，同时返回密钥句柄
Args:	[in]	hSessionHandle:会话句柄；
		[in]	uiKeyBits:指定产生的会话密钥长度
		[in]    uiAlgID：算法标识，指定对称加密算法
		[in]  	uiKEKIndex：密码设备内部存储密钥加密密钥的索引值
		[out]   pucKey :缓冲区指针，用于存放返回的密钥密文
		[out]	puiKeyLength：返回的密钥密文长度
		[out]	phKeyHandle：返回的密钥句柄
备注：加密模式使用ECB加密模式
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_GenerateKeyWithKEK(void *hSessionHandle,unsigned int uiKeyBits,unsigned int uiAlgID,unsigned int uiKEKIndex,unsigned char  *pucKey,unsigned int *puiKeyLength,void **phKeyHandle);
/*=================================================================
Function:SDF_ImportKeyWithKEK
Description:导入会话密钥并用密钥加密密钥解密，同时返回会话密钥句柄
Args:	[in]	hSessionHandle:会话句柄；
		[in]    uiAlgID：算法标识，指定对称加密算法
		[in]  	uiKEKIndex：密码设备内部存储密钥加密密钥的索引值
		[in]    pucKey :缓冲区指针，用于存放返回的密钥密文
		[in]	puiKeyLength：返回的密钥密文长度
		[out]	phKeyHandle：返回的密钥句柄
备注：加密模式使用ECB加密模式
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_ImportKeyWithKEK(void *hSessionHandle,unsigned int uiAlgID,unsigned int uiKEKIndex,unsigned char  *pucKey,unsigned int puiKeyLength,void **phKeyHandle);

/*=================================================================================
Function: SDF_Importkey
Description:导入明文会话密钥，同时返回密钥句柄
Args:	[in]	hSessionHandle:会话句柄；
		[in]	puckey：缓冲区指针，用于存放输入的密钥明文
		[in]    puckey：缓冲区指针，用于存放外部输入的数据
		[in]    puiKeyLength：输入的数据长度
		[out]   phKeyHandle：返回的密钥句柄		
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_ImportKey(void *hSessionHandle,unsigned char *pucKey,unsigned int puiKeyLength,void **phKeyHandle);

/*=================================================================================
Function: SDF_DestroyKey
Description:销毁密钥并释放为密钥句柄分配的内存等资源；
Args:	[in]	hSessionHandle:会话句柄；
		[in]	phKeyHandle:密钥句柄		
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_DestroyKey(void  *hSessionHandle,void *phKeyHandle);


/*=================================================================================
Function: SDF_ExternalVerify_ECC
Description:使用外部ECC公钥对ECC签名值进行验证运算
Args:	[in]	hSessionHandle:会话句柄；
		[in]	uiAlgID：算法标识，指定使用的ECC算法
		[in]	pucPublicKey：外部ECC公钥结构
		[in]  pucDataInput：缓冲区指针，用于存放外部输入的数据
		[in]    uiInputLength：输入的数据长度
		[in]    pucSignature：缓冲区指针，用于存放输入的签名值数据
备注：输入的数据为待签数据的杂凑值，当使用SM2算法时，该输入数据为待签数据经过SM2签名预处理的结果		
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_ExternalVerify_ECC(void  *hSessionHandle,unsigned int uiAlgID,ECCrefPublicKey *pucPublicKey,unsigned char *pucDataInput,unsigned int uiInputLength,ECCSignature *pucSignature);
/*=================================================================================
Function: SDF_InternalSign_ECC
Description:使用内部ECC私钥对数据进行签名运算
Args:	[in]	hSessionHandle:会话句柄；
		[in]	uiISKIndex：密码设备内部存储的ECC签名私钥的索引值
		[in]	pucData：缓冲区指针，用于存放外部输入的数据（输入数据为待签数据的杂凑值）
		[in]    uiDataLength:输入的数据长度
		[out]   pucSignature：缓冲区指针，用于存放输入的签名值得数据
备注：输入的数据为待签数据的杂凑值，当使用SM2算法时，该输入数据为待签数据经过SM2签名预处理的结果
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_InternalSign_ECC(void  *hSessionHandle,unsigned int uiISKIndex,unsigned char *pucData,unsigned int uiDataLength,ECCSignature *pucSignature);
/*=================================================================================
Function: SDF_InternalVerify_ECC
Description:使用内部ECC公钥对ECC签名值进行验证运算
Args:	[in]	hSessionHandle:会话句柄；
		[in]	uiISKIndex：密码设备内部存储的ECC签名公钥的索引值
		[in]	pucData：缓冲区指针，用于存放外部输入的数据（输入数据为待签数据的杂凑值）
		[in]    uiDataLength:输入的数据长度
		[in]    pucSignature：缓冲区指针，用于存放输入的签名值数据
备注：输入的数据为待签数据的杂凑值，当使用SM2算法时，该输入数据为待签数据经过SM2签名预处理的结果
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_InternalVerify_ECC(void  *hSessionHandle,unsigned int uiISKIndex,unsigned char *pucData,unsigned int uiDataLength,ECCSignature *pucSignature);
/*=================================================================================
Function: SDF_ExternalSign_ECC
Description:使用外部ECC私钥对数据进行签名运算
Args:	[in]	hSessionHandle:会话句柄；
		[in]	uiAlgID：算法标识，指定使用的ECC算法
		[in]	pucPrivateKey：外部ECC私钥结构
		[in]  	pucDataInput：缓冲区指针，用于存放外部输入的数据
		[in]    uiInputLength：输入的数据长度
		[in]    pucSignature：缓冲区指针，用于存放输出的签名值数据
备注：输入的数据为待签数据的杂凑值，当使用SM2算法时，该输入数据为待签数据经过SM2签名预处理的结果		
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_ExternalSign_ECC(void  *hSessionHandle,unsigned int uiAlgID,ECCrefPrivateKey *pucPrivateKey,unsigned char *pucDataInput,unsigned int uiInputLength,ECCSignature *pucSignature);

/*=================================================================================
Function: SDF_ExternalEncrypt_ECC
Description:使用外部ECC公钥对数据进行加密运算
Args:	[in]	hSessionHandle:会话句柄；
		[in]	uiAlgID：算法标识，指定使用的ECC算法
		[in]	pucPublicKey：外部ECC公钥结构
		[in]    pucData：缓冲区指针，用于存放外部输入的数据
		[in]    uiDataLength：输入的数据长度
		[out]   pucEncData：缓冲区指针，用于存放输出的数据密文		
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_ExternalEncrypt_ECC(void  *hSessionHandle,unsigned int uiAlgID,ECCrefPublicKey *pucPublicKey,unsigned char *pucData,unsigned int uiDataLength,ECCCipher *pucEncData);
/*=================================================================================
Function: SDF_ExternalDecrypt_ECC
Description:使用外部ECC私钥对数据进行解密运算
Args:	[in]	hSessionHandle:会话句柄；
		[in]	uiAlgID：算法标识，指定使用的ECC算法
		[in]	pucPrivateKey：外部ECC私钥结构
		[in]    pucEncData：缓冲区指针，用于存放外部输入的数据
		[out]    pucData：输入的数据长度
		[out]   puiDataLength：缓冲区指针，用于存放输出的数据密文		
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDF_ExternalDecrypt_ECC(void  *hSessionHandle,unsigned int uiAlgID,ECCrefPrivateKey *pucPrivateKey,ECCCipher *pucEncData,unsigned char* pucData,unsigned int *puiDataLength);

/*=================================================================================
Function: SDFEI_HashUpdateEnd
Description:杂凑运算定制接口，对输入的明文进行杂凑运算输出结果但运算不结束
Args:	[in]	hSessionHandle:会话句柄；
		[in]    pucData：缓冲区指针用于存放输入的数据明文
	    [in]    uiDataLength：输入的数据明文长度
	   	[out]   pucHash：缓冲区指针，用于存放输出的杂凑数据
	    [out]   puiHashLength：返回的杂凑数据长度
Return:正确返回SDR_OK，错误返回错误代码；
=================================================================================*/
int SDFEI_HashUpdateEnd(void *hSessionHandle,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucHash,unsigned int *puiHashLength);

//HMAC运算类函数
/*=================================================================================
Function: SDFEI_HmacInit
Description:三步式数据HMAC运算第一步
Args:	[in]	hSessionHandle:会话句柄；
		[in]	phKeyHandle：密钥句柄
Return:正确返回SDR_OK，错误返回错误代码；
==========================================================*/
int SDFEI_HmacInit(void *hSessionHandle,void *phKeyHandle);

/*=================================================================================
Function: SDFEI_HmacUpdate
Description:三步式数据HMAC运算第二步，对输入的明文进行杂凑运算
Args:	[in]	hSessionHandle:会话句柄；
		[in]    pucData：缓冲区指针用于存放输入的数据明文
	   [in]    uiDataLength：输入的数据明文长度
Return:正确返回SDR_OK，错误返回错误代码；
=================================================================================*/
int SDFEI_HmacUpdate(void *hSessionHandle,unsigned char *pucData,unsigned int uiDataLength);

/*=================================================================================
Function: SDFEI_HmacFinal
Description:三步式数据HMAC运算第三步，杂凑运算结束返回杂凑数据并清除中间数据
Args:	[in]	hSessionHandle:会话句柄；
		[out]   pucHash：缓冲区指针，用于存放输出的杂凑数据
	   [out]   uiHashLength：返回的杂凑数据长度
Return:正确返回SDR_OK，错误返回错误代码；
=================================================================================*/
int SDFEI_HmacFinal(void  *hSessionHandle,unsigned char *pucData,unsigned int *puiHashLength);

/*=================================================================================
Function: SDFEI_HkdfExtract
Description:密钥派生相关
Args:	[in]	hSessionHandle:会话句柄；
		[in]	phKeyHandle：密钥句柄
		[in]    pucData：缓冲区指针用于存放输入的数据明文
	    [in]    uiDataLength：输入的数据明文长度  最大7K字节
	    [out]	phKeyOutHandle：密钥句柄
Return:正确返回SDR_OK，错误返回错误代码；
=================================================================================*/
int SDFEI_HkdfExtract(void *hSessionHandle,void *phKeyHandle,unsigned char *pucData,unsigned int uiDataLength,void **phKeyOutHandle);

#if 0
#define RSAref_MAX_BITS               2048
#define RSAref_MAX_LEN                ((RSAref_MAX_BITS + 7)/8)
#define RSAref_MAX_PBITS              ((RSAref_MAX_BITS + 1)/2)
#define RSAref_MAX_PLEN               ((RSAref_MAX_PBITS + 7)/8)



// SecretKey Manager
// RSA 公钥结构
typedef struct RSArefPublicKey_st {
	unsigned int  bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

// RSA 私钥结构
typedef struct RSArefPrivateKey_st {
	unsigned int  bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
	unsigned char d[RSAref_MAX_LEN];
	unsigned char prime[2][RSAref_MAX_PLEN];
	unsigned char pexp[2][RSAref_MAX_PLEN];
	unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;





/**   6.3.1
*  功能描述：导出密码设备内部存储的指定索引的签名公钥
*  参数： hSessionHandle【in】 已经打开设备句柄
*         uiKeyIndex[in]     密码设备存储私钥索引
*         pucPublicKey[out]  RSA公钥结构
*  返回值：0  成功； 非0  失败，返回错误代码
*  备注： 本标准涉及密码设备存储的密钥对索引值的的起始索引值为１，最大为 狀 ，密码设备的实 际存储容量决定 狀 值
**/

int SDF_ExportSignPublicKey_RSA(void* hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey* pucPublicKey);
/**  6.3.2
*  功能描述：导出密码设备内部存储的指定索引的加密公钥
*  参数： hSessionHandle【in】 已经打开设备句柄
*         uiKeyIndex[in]     密码设备存储私钥索引
*         pucPublicKey[out]  RSA公钥结构
*  返回值：0  成功； 非0  失败，返回错误代码
*
**/

int SDF_ExportEncPublicKey_RSA(void* hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey* pucPublicKey);

/**  6.3.3
*  功能描述：请求密码设备产生指定模长的RSA密钥对
*  参数： hSessionHandle【in】 已经打开设备句柄
*         uiKeyBits【in】      指定密钥模长
*         pucPublicKey[out]    RSA公钥结构
*         pucPrivateKey[out]   RSA私钥结构
*  返回值：0  成功； 非0  失败，返回错误代码
*
**/

int SDF_GenerateKeyPair_RSA(void* hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey* pucPublicKey, RSArefPrivateKey* pucPrivateKey);


/**   6.3.4
*  功能描述：生成会话密钥并用内部RSA公钥加密输出
*  参数： hSessionHandle【in】 已经打开设备句柄
*         uiPKIndex【in】      密码设备内部存储公钥索引
*         uiKeyBits【in】      指定产生会话密钥长度
*         pucKey[out]          缓冲区指针，用于存放返回的密钥密文
*         puiKeyLength[out]    返回的密钥密文长度
*         phKeyHandle[out]     返回的密钥句柄
*  返回值：0  成功； 非0  失败，返回错误代码
*  备注： 公钥加密数据时填充方式按照ＰＫＣＳ＃１ｖ １． ５的要求进行
**/

int SDF_GenerateKeyWithIPK_RSA(void* hSessionHandle, unsigned int uiPKIndex, unsigned int uiKeyBits, unsigned char* pucKey, unsigned int* puiKeyLength, void** phKeyHandle);


/**   6.3.5
*  功能描述：生成会话密钥并用外部RSA公钥加密输出
*  参数： hSessionHandle【in】 已经打开设备句柄
*         uiKeyBits【in】      指定产生会话密钥长度
*         pucPublicKey【in】   输入的外部RSA公钥结构
*         pucKey[out]          缓冲区指针，用于存放返回的密钥密文
*         puiKeyLength[out]    返回的密钥密文长度
*         phKeyHandle[out]     返回的密钥句柄
*  返回值：0  成功； 非0  失败，返回错误代码
*  备注： 公钥加密数据时填充方式按照ＰＫＣＳ＃１ｖ １． ５的要求进行
**/

int SDF_GenerateKeyWithEPK_RSA(void* hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey* pucPublicKey, unsigned char* pucKey, unsigned int* puiKeyLength, void** phKeyHandle);


/**  6.3.6
*  功能描述：导入会话密钥并用内部RSA私钥解密
*  参数： hSessionHandle【in】 已经打开设备句柄
*         uiISKIndex【in】     密码设备内部存储加密私钥的索引值，对应于加密时候的公钥
*         pucKey[in]          缓冲区指针，用于存放返回的密钥密文
*         puiKeyLength[in]    返回的密钥密文长度
*         phKeyHandle[out]     返回的密钥句柄
*  返回值：0  成功； 非0  失败，返回错误代码
*  备注： 公钥加密数据时填充方式按照ＰＫＣＳ＃１ｖ １． ５的要求进行
**/

int SDF_ImportKeyWithISK_RSA(void* hSessionHandle, unsigned int uiISKeyIndex, unsigned char* pucKey, unsigned int puiKeyLength, void** phKeyHandle);

/**   6.3.7
*  功能描述：将由内部加密公钥加密的会话密钥转换为由指定外部公钥加密，可用于数字信封转换
*  参数： hSessionHandle【in】 已经打开设备会话句柄
*         uiKeyIndex【in】     密码设备内部存储的RSA密钥的索引值
*         pucPublicKey[in]     外部RSA公钥结构
*         pucDEInput[in]       缓冲区指针，用于存放输入的会话密钥密文
*         uiDELength[in]       输入的会话密钥密文长度
*         pucDEOutput[out]     缓冲区指针，用于存放输出的转换后的会话密钥密文
*         puiDELength[out]     返回转换后的会话密钥密文长度
*  返回值：0  成功； 非0  失败，返回错误代码
*  备注： 公钥加密数据时填充方式按照ＰＫＣＳ＃１ｖ １． ５的要求进行
**/

int SDF_ExchangeDigitEnvelopeBaseOnRSA(void* hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey* pucPublicKey, unsigned char* pucDEInput, unsigned int uiDELength, unsigned char* pucDEOutput, unsigned int* puiDELength);


/**   6.4.1
*  功能描述：指定使用外部公钥对数据进行运算
*  参数： hSessionHandle【in】      与设备建立的会话句柄
*         pucPublicKey[in]          外部RSA公钥结构
*         pucDataInput[in]          缓冲器指针，用于存放输入的数据
*         uiInputLength[in]         输入数据长度
*         pucDataOutput[out]        缓冲器指针，用于存放输出的数据
*         puiOutputLength[out]      输出数据长度
*  返回值：0  成功； 非0  失败，返回错误代码
*  备注： 数据格式由应用层封装
**/

int SDF_ExternalPublicKeyOperation_RSA(void* hSessionHandle, RSArefPublicKey* pucPublicKey, unsigned char* pucDataInput, unsigned int uiInputLength, unsigned char* pucDataOutput, unsigned int* puiOutputLength);

/**   6.4.2
*  功能描述：指定使用外部私钥对数据进行运算
*  参数： hSessionHandle【in】      与设备建立的会话句柄
*         pucPrivateKey[in]         外部RSA私钥结构
*         pucDataInput[in]          缓冲器指针，用于存放输入的数据
*         uiInputLength[in]         输入数据长度
*         pucDataOutput[out]        缓冲器指针，用于存放输出的数据
*         puiOutputLength[out]      输出数据长度
*  返回值：0  成功； 非0  失败，返回错误代码
*  备注： 数据格式由应用层封装
**/

int SDF_ExternalPrivateKeyOperation_RSA(void* hSessionHandle, RSArefPrivateKey* pucPrivateKey, unsigned char* pucDataInput, unsigned int uiInputLength, unsigned char* pucDataOutput, unsigned int* puiOutputLength);

/**   6.4.3
*  功能描述：指定使用内部公钥对数据进行运算
*  参数： hSessionHandle【in】      与设备建立的会话句柄
*         uiKeyIndex[in]            密码设备内部存储公钥的索引值
*         pucDataInput[in]          缓冲器指针，用于存放输入的数据
*         uiInputLength[in]         输入数据长度
*         pucDataOutput[out]        缓冲器指针，用于存放输出的数据
*         puiOutputLength[out]      输出数据长度
*  返回值：0  成功； 非0  失败，返回错误代码
*  备注：  索引范围仅限于内部签名密钥对，数据格式由应用层封装
**/

int SDF_InternalPublicKeyOperation_RSA(void* hSessionHandle, unsigned int uiKeyIndex, unsigned char* pucDataInput, unsigned int uiInputLength, unsigned char* pucDataOutput, unsigned int* puiOutputLength);

/**   6.4.4
*  功能描述：指定使用内部指定索引的私钥对数据进行运算
*  参数： hSessionHandle【in】      与设备建立的会话句柄
*         uiKeyIndex[in]            密码设备内部存储私钥的索引值
*         pucDataInput[in]          缓冲器指针，用于存放输入的数据
*         uiInputLength[in]         输入数据长度
*         pucDataOutput[out]        缓冲器指针，用于存放输出的数据
*         puiOutputLength[out]      输出数据长度
*  返回值：0  成功； 非0  失败，返回错误代码
*  备注：  索引范围仅限于内部签名密钥对，数据格式由应用层封装
**/

int SDF_InternalPrivateKeyOperation_RSA(void* hSessionHandle, unsigned int uiKeyIndex, unsigned char* pucDataInput, unsigned int uiInputLength, unsigned char* pucDataOutput, unsigned int* puiOutputLength);

#endif





//C++ End
#ifdef __cplusplus
}
#endif



#endif	//_HSM_SDK_H_


