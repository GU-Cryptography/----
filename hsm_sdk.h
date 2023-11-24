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
 * ͷ�ļ�
 */
 

//#include "hsm_common.h"

//C++ Start
#ifdef __cplusplus
extern "C" {
#endif





#define SDR_OK 					0 
#define SDR_BASE 				0x1000000 			//���������ֵ
#define SDR_UNKNOWERR 			SDR_BASE+0x00000001 //δ֪����
#define SDR_NOTSUPPORT 			SDR_BASE+0x00000002 //��֧�ֵĽӿڵ���
#define SDR_COMMFAIL 			SDR_BASE+0x00000003 //���豸ͨ��ʧ��
#define SDR_HARDFAIL 			SDR_BASE+0x00000004 //����ģ��Ԫ��Ӧ
#define SDR_OPENDEVICE 			SDR_BASE+0x00000005 //���豸ʧ��
#define SDR_OPENSESSION 		SDR_BASE+0x00000006 //�����Ựʧ��
#define SDR_PARDENY 			SDR_BASE+0x00000007 //��˽Կʹ��Ȩ��
#define SDR_KEYNOTEXIST 		SDR_BASE+0x00000008 //�����ڵ���Կ����
#define SDR_ALGNOTSUPPORT 		SDR_BASE+0x00000009 //��֧�ֵ��㷨����
#define SDR_ALGMODNOTSUPPORT 	SDR_BASE+0x0000000A //��֧�ֵ��㷨ģʽ����
#define SDR_PKOPERR 			SDR_BASE+0x0000000B //��Կ����ʧ��
#define SDR_SKOPERR 			SDR_BASE+0x0000000C //˽Կ����ʧ��
#define SDR_SIGNERR 			SDR_BASE+0x0000000D //ǩ������ʧ��
#define SDR_VERIFYERR 			SDR_BASE+0x0000000E //��֤ǩ��ʧ��
#define SDR_SYMOPERR 			SDR_BASE+0x0000000F //�Գ��㷨����ʧ��
#define SDR_STEPERR 			SDR_BASE+0x00000010 //�ಽ���㲽�����
#define SDR_FILESIZEERR 		SDR_BASE+0x00000011 //�ļ����ȳ�������
#define SDR_FILENOEXIST 		SDR_BASE+0x00000012 //ָ�����ļ�������
#define SDR_FILEOFSERR 			SDR_BASE+0x00000013 //�ļ���ʼλ�ô���
#define SDR_KEYTYPEERR 			SDR_BASE+0x00000014 //��Կ���ʹ���
#define SDR_KEYERR 				SDR_BASE+0x00000015 //��Կ����
#define SDR_ENCDATAERR 			SDR_BASE+0x00000016 //ECC �������ݴ���
#define SDR_RANDERR 			SDR_BASE+0x00000017 //���������ʧ��
#define SDR_PRKRERR 			SDR_BASE+0x00000018 //˽Կʹ��Ȩ�޻�ȡʧ��
#define SDR_MACERR 				SDR_BASE+0x00000019 //MAC ����ʧ��
#define SDR_FILEEXISTS 			SDR_BASE+0x0000001A //ָ���ļ��ȴ���
#define SDR_FILEWERR 			SDR_BASE+0x0000001B //�ļ�д��ʧ��
#define SDR_NOBUFFER 			SDR_BASE+0x0000001C //�洢�ռ䲻��
#define SDR_INARGERR 			SDR_BASE+0x0000001D //���˲�������
#define SDR_OUTARGERR 			SDR_BASE+0x0000001E //�����������
#define	SDR_TASKRUNERR			 SDR_BASE+0x00000020	//һ���Ựͬʱ���ö������
#define	SDR_CARDSTATERR		     SDR_BASE+0x0000009A	//���ܿ�״̬����δ��֤ͨ�����û�Ȩ�޴���δ�������״̬��
#define	SDR_START_CONFIG	     SDR_BASE+0x00000022	//�������ã�ֹͣһ���������㣬������
#define SDR_MALLOCERR			 SDR_BASE+0x00000023	//�����ڴ�ʧ��
#define SDR_ACESSPIN_LOCKED			 SDR_BASE+0x00000024	//���ʿ����뱻����

#define SDR_TASK_RUNNING		SDR_BASE+0x00000025			//��������
#define SDR_RETURN_TASKLENERR	SDR_BASE+0x00000026			//�������񳤶ȴ���
#define SDR_RETURN_TASKTYPEERR	SDR_BASE+0x00000027			//�����������ʹ���
#define SDR_SERIALNUMERR		SDR_BASE+0x00000028			//���صĴ��Ų���
#define SDR_TASKLEN_TOOLONG		SDR_BASE+0x00000029			//���񳤶ȴ���ͨ�ſ��С
#define SDR_WRITE_ASYMKEYERR	SDR_BASE+0x0000002A			//д��ǶԳ���Կʧ�ܣ���Կ��������
#define SDR_WRITE_SYMKEYERR		SDR_BASE+0x0000002B			//д��Գ���Կ����Կ��������
#define SDR_ERASE_ASYMKEYERR	SDR_BASE+0x0000002C			//�����ǶԳ���Կʧ�ܣ���Կ��������
#define SDR_ERASE_SYMKEYERR		SDR_BASE+0x0000002D			//�����Գ���Կʧ�ܣ���Կ��������
#define SDR_READ_ASYMKEYERR		SDR_BASE+0x0000002E			//��ȡ�ǶԳ���Կʧ�ܣ���Կ��������
#define SDR_READ_SYMKEYERR		SDR_BASE+0x0000002F			//��ȡ�Գ���Կʧ�ܣ���Կ��������
#define SDR_HASH_CALCERR		SDR_BASE+0x00000030			//hash_calcʧ��
#define SDR_HASH_COMPAREERR		SDR_BASE+0x00000031			//hash����ԱȲ�һ��
#define SDR_HASH_INITERR		SDR_BASE+0x00000032			//Hash_initʧ��
#define SDR_HASH_UPDATEERR		SDR_BASE+0x00000033			//Hash_updataʧ��
#define SDR_HASH_ENDERR			SDR_BASE+0x00000034			//Hash_updataʧ��
#define SDR_READ_IFLASH_4KERR	SDR_BASE+0x00000035			//read_iflash_4k��ȡʧ��
#define SDR_READ_FILEERR		SDR_BASE+0x00000036			//��ȡ�ļ�ʧ��
#define SDR_PAGE_EARSEERR		SDR_BASE+0x00000037			//page_earse����ʧ��
#define SDR_SM2_KEY_GENERATE	SDR_BASE+0x00000038			//sm2_key_generate������Կ��ʧ��
#define SDR_WRITE_SESSIONKEYERR	SDR_BASE+0x00000039			//�洢�Ự��Կ����ʧ��
#define SDR_ECCGENERATEKEYERR	SDR_BASE+0x0000003A			//EccGenerateKeyPair ECC������Կ��ʧ��
#define SDR_SM3_CALS_ZERR		SDR_BASE+0x0000003B			//sm3_calc_zʧ��
#define SDR_ECC_KEYEXCHANGE_HTERR	SDR_BASE+0x0000003C		//ECC��Կ����ʧ��
#define SDR_ECCDECRYPTERR		SDR_BASE+0x0000003D			//ECCDecrypt ECC����ʧ��
#define SDR_ECCENCRYPTERR		SDR_BASE+0x0000003E			//ECCEncrypt ECC����ʧ��
#define SDR_CHANGEPINERR		SDR_BASE+0x0000003F			//Sdf_ChangePIN ����˽ԿȨ�޿���ʧ��


/*�ǶԳ��㷨��ʶ����*/
#if 0
#define SGD_SM2				0x00020000				//SM2��Բ���������㷨
#define SGD_SM2_1				0x00020100				//SM2��Բ����ǩ���㷨
#define SGD_SM2_2				0x00020200				//SM2��Բ������Կ����Э��
#define SGD_SM2_3				0x00020400				//SM2��Բ���߼����㷨
#else
#define SGD_RSA                         0x00010000
#define SGD_SM2				0x00020000				//SM2��Բ���������㷨
#define SGD_ECC                         0x00020000
#define SGD_SM2_1                       0x00020200
#define SGD_SM2_2                       0x00020400
#define SGD_SM2_3                       0x00020800
#endif



/*�Գ��㷨��ʶ����*/
#define SGD_SM1_ECB   			0x00000101				//SM1�㷨 ECB����ģʽ		
#define SGD_SM1_CBC   			0x00000102				//SM1�㷨 CBC����ģʽ
#define SGD_SM1_CFB   			0x00000104				//SM1�㷨 CFB����ģʽ
#define SGD_SM1_OFB   			0x00000108				//SM1�㷨 OFB����ģʽ
#define SGD_SM1_MAC   			0x00000110				//SM1�㷨 MAC����
////////////////////SSF33/////////////////
#define SGD_SF33_ECB    		0x00000201				//SSF33�㷨 ECB����ģʽ
#define SGD_SF33_CBC    		0x00000202				//SSF33�㷨 CBC����ģʽ
#define SGD_SF33_CFB    		0x00000204				//SSF33�㷨 CFB����ģʽ
#define SGD_SF33_OFB   		 	0x00000208				//SSF33�㷨 OFB����ģʽ
#define SGD_SF33_MAC    		0x00000210				//SSF33�㷨 MAC����
////////////////////SM4///////////////////
#define SGD_SM4_ECB   			0x00000401				//SM4�㷨 ECB����ģʽ
#define SGD_SM4_CBC   			0x00000402				//SM4�㷨 CBC����ģʽ
#define SGD_SM4_CFB   			0x00000404				//SM4�㷨 CFB����ģʽ
#define SGD_SM4_OFB   			0x00000408				//SM4�㷨 OFB����ģʽ
#define SGD_SM4_MAC   			0x00000410				//SM4�㷨 MAC����
////////////////////ZUC///////////////////
#define SGD_ZUC_EEA3   			0x00000801				//ZUC���֮�������㷨 128-EEA3�㷨
#define SGD_ZUC_EIA3   			0x00000802				//ZUC���֮�������㷨 128-EIA3�㷨

/*�Ӵ����㷨��ʶ����*/
#define	SGD_SM3 				0x00000001				//SM3�Ӵ��㷨
#define	SGD_SHA1 				0x00000002				//SHA_1�Ӵ��㷨
#define	SGD_SHA256 				0x00000004				//SHA_256�Ӵ��㷨



#define ECCref_MAX_BITS 			512
#define ECCref_MAX_LEN  			((ECCref_MAX_BITS+7)/8)




/*ECC��Կ�ṹ��*/
typedef struct ECCrefPublicKey_st
{
	unsigned int bits;//��Կģ��
	unsigned char x[ECCref_MAX_LEN];//X����
	unsigned char y[ECCref_MAX_LEN];//Y����
}ECCrefPublicKey;



/*ECC˽Կ�ṹ��*/
typedef struct ECCrefPrivateKey_st
{
	unsigned int  bits; //��Կģ��
	unsigned char K[ECCref_MAX_LEN];//˽Կ
}ECCrefPrivateKey;

/*ECCǩ�����ݽṹ��*/
typedef struct ECCSignature_st
{
	unsigned char r[ECCref_MAX_LEN];//ǩ��r��������
	unsigned char s[ECCref_MAX_LEN];//ǩ��s��������
}ECCSignature;


/*ECC�������ݽṹ��*/
typedef struct ECCCipher_st
{
	unsigned char x[ECCref_MAX_LEN];//x����
	unsigned char y[ECCref_MAX_LEN];//y����
	unsigned char M[32];//�����Ӵ�ֵ
	unsigned int  L;//�������ݳ���
	unsigned char C[1];//��������
}ECCCipher;


/*�豸��Ϣ*/
typedef struct DEVICEINFO_st
{
	unsigned char   IssuerName[40]; 		//����������
	unsigned char   DeviceName[16];			//�豸�ͺ�
	/*�豸���Ű������ڣ�8�ַ��������Σ�3�ַ�����ˮ�ţ�5�ַ���������λʱ��0��
	���磺20080229-001-00123��ʾΪ0x 20 08 02 29 00 10 01 23*/
	unsigned char  	DeviceSerial[16];		
	unsigned int    DeviceVersion;			//�����豸����汾��
	unsigned int    StandardVersion;		//�����豸֧�ֽӿڹ淶�汾��
	unsigned int 	AsymAlgAbility[2];		//֧�ַǶԳ��㷨
	unsigned int    SymAlgAbility;			//֧�ֶԳ��㷨
	unsigned int    HashAlgAbility;			//֧�ֵ��Ӵ��㷨
	unsigned int    BufferSize;				//֧���ļ����洢�ռ�
}
__attribute__ ((packed))
DEVICEINFO;


/*
 * ����ʵ��
 */


/*=========================================================
Function:SDF_OpenDevice
Description:�����в���֮ǰҪ���д��豸������������������������
Args:       [out] phDeviceHandle:�豸�����
Return:		��ȷ����SDR_0K�����󷵻ش�����뷵�ش��󷵻ش��������롣
=========================================================*/
int SDF_OpenDevice(void **phDeviceHandle);

/*========================================================
Function:SDF_CloseSession
Description:�����в���֮��Ҫ�����豸����ر���Ӧ�豸��
Args:		[in] hDeviceHandle���豸�����
Return:		��ȷ����SDR_0K�����󷵻ش�����뷵�ش��󷵻ش���������ֱ��������
=========================================================*/
int SDF_CloseDevice(void* hDeviceHandle);

/*=========================================================
Function:SDF_OpenSession
Description:�����������豸�ĻỰ��
Args:	[in] hDeviceHandle:�豸�����
		[out] phSessionHandle���Ự���
Return:	��ȷ����SDR_0K�����󷵻ش�����뷵�ش��󷵻ش��������롣
=========================================================*/
int SDF_OpenSession( void* hDeviceHandle,void **phSessionHandle);

/*========================================================
Function:SDF_CloseSession
Description:�ر��������豸�ѽ����ĻỰ���ͷ������Դ
Args:	[in] hSessinHandle���Ự�����
Return:	��ȷ����SDR_OK�����󷵻ش�����뷵�ش��󷵻ش��������롣
==========================================================*/
int SDF_CloseSession(void* hSessinHandle);

/*=========================================================
Function:SDF_GetDeviceInfo
Description:
Args:	[in] hSessionHandle:�豸�����
		[out] pstDeviceInfo:�豸��Ϣ��
Return:��ȷ����SDR_OK�����󷵻ش�����뷵�ش��󷵻ش��������롣
==========================================================*/
int SDF_GetDeviceInfo(void* hSessionHandle,DEVICEINFO*  pstDeviceInfo);

/*=================================================================
Function:SDF_GenerateRandom
Description:���������豸����ָ�����ȵ������
Args:	[in]	hSessionHandle:�豸�����
		[in]	uiLength:��Ҫ����������ĳ��ȣ�
		[out]	pData:������ָ���Ų������������
Return:��ȷ����0�����󷵻ش�����룻
==========================================================*/
int SDF_GenerateRandom(void* hSessionHandle,unsigned int uiLength,unsigned char* pucRandom);

/*=================================================================
Function:SDF_GetPrivateKeyAccessRight
Description:��ȡ�����豸�ڲ��洢��ָ������˽Կ��ʹ��Ȩ
Args:	    [in]	hSessionHandle:�Ự�����
			[in]	uiKeyIndex�������豸�洢˽Կ������ֵ		
			[in]    pucPassword��ʹ��˽ԿȨ�޵ı�ʶ��
		    [in]    uiPwdLength��˽Կ���ʿ����볤�ȣ�������8�ֽ�
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_GetPrivateKeyAccessRight(void* hSessionHandle,unsigned int uiKeyIndex,unsigned char* pucPassword,unsigned int uiPwdLength);

/*=================================================================
Function:SDF_ReleasePrivateKeyAccessRight
Description:�ͷ������豸�ڲ��洢��ָ������˽Կ��ʹ��Ȩ
Args:	[in]	hSessionHandle:�Ự�����
		[in]	uiKeyIndex�������豸�洢˽Կ������ֵ			
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_ReleasePrivateKeyAccessRight(void* hSessionHandle,unsigned int uiKeyIndex);

//�Գ�����ӽ���
/*=================================================================================
Function: SDF_Encrypt
Description:ʹ��ָ������Կ�����IV�����ݽ��жԳƼ�������
Args:	[in]	hSessionHandle:�Ự�����
		[in]	phKeyHandle:��Կ���
		[in]	uiAlgID:�㷨��ʶָ���ԳƼ����㷨
		[in/out]    pucIV:������ָ�룬���ڴ������ͷ��ص�IV����
		[in]    pucData:������ָ�룬���ڴ���������������
	    [in]    uiDataLength��������������ĳ���
		[out]   pucEncData��������ָ�룬���ڴ���������������
		[out]   puiEncDataLength��������������ĳ���
��ע���˺����������ݽ�����䴦����������ݱ�����ָ���㷨���鳤�ȵ�������		
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_Encrypt(void  *hSessionHandle,void *phKeyHandle,unsigned int uiAlgID,unsigned char *pucIV,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucEncData,unsigned int *puiEncDatalength);

/*=================================================================================
Function: SDF_Decrypt
Description:ʹ��ָ������Կ�����IV�����ݽ��жԳƽ�������
Args:[in]	hSessionHandle:�Ự�����
	[in]	phKeyHandle:��Կ���
	[in]	uiAlgID:�㷨��ʶָ���ԳƼ����㷨
	[in/out]    pucIV:������ָ�룬���ڴ������ͷ��ص�IV����
	[in]    pucData:������ָ�룬���ڴ���������������
	[in]    uiDataLength��������������ĳ���
	[out]   pucEncData��������ָ�룬���ڴ���������������
	[out]   puiEncDataLength��������������ĳ���
��ע���˺����������ݽ�����䴦����������ݱ�����ָ���㷨���鳤�ȵ�������
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_Decrypt(void *hSessionHandle,void *phKeyHandle,unsigned int uiAlgID,unsigned char *pucIV,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucEncData,unsigned int *puiEncDataLength);

/*=================================================================================
Function: SDF_CalculateMAC
Description:
Args:[in]	hSessionHandle:�Ự�����
	 [in]	phKeyHandle:��Կ���
	 [in]	uiAlgID:�㷨��ʶָ��MAC�����㷨
	 [in/out]    pucIV:������ָ�룬���ڴ������ͷ��ص�IV����
	 [in]    pucData:������ָ�룬���ڴ���������������
	 [in]    uiDataLength��������������ĳ���
	 [out]   pucMAC��������ָ�룬���ڴ�������MACֵ
	 [out]   puiMACLength�������MACֵ����
��ע���˺����������ݽ��зְ������������MAC������IV��������MACֵ	
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_CalculateMAC(void  *hSessionHandle,void *phKeyHandle,unsigned int uiAlgID,unsigned char *pucIV,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucMAC,unsigned int *puiMACLength);
//�Ӵ��㷨�ຯ��
/*=================================================================================
Function: SDF_HashInit
Description:����ʽ�����Ӵ������һ��
Args:	[in]	hSessionHandle:�Ự�����
		[in]	uiAlgID��ָ���Ӵ��㷨��ʶ
	    [in] 	pucPublicKey��ǩ���߹�Կ�����㷨��ʶΪSGD_SM3ʱ��Ч
		[in]    pucID��ǩ����IDֵ�����㷨��ʶΪSGD_SM3ʱ��Ч
	    [in]    uiIDLength��ǩ���ߵ�ID���ȣ����㷨��ʶΪSGD_SM3ʱ��Ч
��ע��uiIDLength���Ȳ�Ϊ0��	uiAlgIDΪSGD_SM3ʱ����ִ��SM2��Ԥ����1����	
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_HashInit(void  *hSessionHandle,unsigned int uiAlgID,ECCrefPublicKey *pucPublicKey,unsigned char *pucID,unsigned int uiIDLength);

/*=================================================================================
Function: SDF_HashUpdate
Description:����ʽ�����Ӵ�����ڶ���������������Ľ����Ӵ�����
Args:	[in]	hSessionHandle:�Ự�����
		[in]    pucData��������ָ�����ڴ���������������
	   [in]    uiDataLength��������������ĳ���
Return:��ȷ����SDR_OK�����󷵻ش�����룻
=================================================================================*/
int SDF_HashUpdate(void  *hSessionHandle,unsigned char *pucData,unsigned int uiDataLength);

/*=================================================================================
Function: SDF_HashFinal
Description:����ʽ�����Ӵ�����ڶ������Ӵ�������������Ӵ����ݲ�����м�����
Args:	[in]	hSessionHandle:�Ự�����
		[out]   pucHash��������ָ�룬���ڴ��������Ӵ�����
	   [out]   uiHashLength�����ص��Ӵ����ݳ���
Return:��ȷ����SDR_OK�����󷵻ش�����룻
=================================================================================*/
int SDF_HashFinal(void  *hSessionHandle,unsigned char *pucData,unsigned int *puiHashLength);

//�ļ�����
/*=================================================================================
Function: SDF_CreatFile
Description:�������豸�ڲ��������ڴ洢�û����ݵ��ļ�
Args:	[in]	hSessionHandle:�Ự�����
		[in]    pucFileName��������ָ�����ڴ��������ļ�������󳤶�128�ֽ�
	   	[in]    uiNameLen���ļ�������
		[in]    uiFileSize���ļ���ռ�洢�ռ�ĳ���
Return:��ȷ����SDR_OK�����󷵻ش�����룻
=================================================================================*/
int SDF_CreateFile(void  *hSessionHandle,unsigned char *pucFileName,unsigned int uiNameLen,unsigned int   uiFileSize);
/*=================================================================================
Function: SDF_ReadFile
Description:��ȡ�������豸�ڲ��洢�û����ݵ��ļ�����
Args:	[in]	hSessionHandle:�Ự�����
		[in]    pucFileName��������ָ�����ڴ��������ļ�������󳤶�128�ֽ�
	   	[in]    uiNameLen���ļ�������
		[in]    uiOffset��ָ����ȡ�ļ�ʱ��ƫ��ֵ
		[in|out] puiFileLength�����ʱָ����ȡ�ļ����ݵĳ��ȣ�����ʱ����ʵ�ʶ�ȡ�ļ����ݵĳ���
		[out]   pucbuffer��������ָ�룬���ڴ�Ŷ�ȡ���ļ�����
Return:��ȷ����SDR_OK�����󷵻ش�����룻
=================================================================================*/
int SDF_ReadFile(void  *hSessionHandle,unsigned char *pucFileName,unsigned int uiNameLen,unsigned int uiOffset, unsigned int  *puiFileLength, unsigned char *pucbuffer);
/*=================================================================================
Function: SDF_WriteFile
Description:�������豸�ڲ��洢�û������ļ���д������
Args:	[in]	hSessionHandle:�Ự�����
		[in]    pucFileName��������ָ�����ڴ��������ļ�������󳤶�128�ֽ�
	   	[in]    uiNameLen���ļ�������
		[in]    uiOffset��ָ��д���ļ�ʱ��ƫ��ֵ
		[in] puiFileLengthָ��д���ļ����ݵĳ���
		[in]   pucbuffer��������ָ�룬���ڴ�������д�ļ�����
Return:��ȷ����SDR_OK�����󷵻ش�����룻
=================================================================================*/
int SDF_WriteFile(void  *hSessionHandle,unsigned char *pucFileName,unsigned int uiNameLen,unsigned int uiOffset, unsigned int  uiFileLength, unsigned char *pucbuffer);
/*=================================================================================
Function: SDF_DeleteFile
Description:ɾ��ָ���ļ����������豸�ڲ��洢�û����ݵ��ļ�
Args:	[in]	hSessionHandle:�Ự�����
		[in]    pucFileName��������ָ�����ڴ��������ļ�������󳤶�128�ֽ�
	   [in]    uiNameLen���ļ�������
Return:��ȷ����SDR_OK�����󷵻ش�����룻
=================================================================================*/
int SDF_DeleteFile(void  *hSessionHandle,unsigned char *pucFileName,unsigned int uiNameLen);



//��Կ������
/*=================================================================
Function:SDF_ExportSignPublicKey_ECC
Description:���������豸�ڲ��洢��ָ������λ�õ�ECCǩ����Կ
Args:	[in]	hSessionHandle:�Ự�����
		[in]	uiKeyIndex�������豸�洢��ECC��Կ������ֵ
		[out] pucPublicKey��ECC��Կ�ṹ
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_ExportSignPublicKey_ECC(void *hSessionHandle,unsigned int uiKeyIndex,ECCrefPublicKey *pucPublicKey);
/*=================================================================
Function:SDF_ExportEncPublicKey_ECC
Description:���������豸�ڲ��洢��ָ������λ�õ�ECC���ܹ�Կ
Args:	[in]	hSessionHandle:�Ự�����
		[in]    uiKeyIndex�������豸�洢��ECC��Կ������ֵ
		[out]   pucPublicKey:ECC��Կ�ṹ
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_ExportEncPublicKey_ECC(void *hSessionHandle,unsigned int uiKeyIndex,ECCrefPublicKey *pucPublicKey);
/*=================================================================
Function:SDF_GenerateKeyPair_ECC
Description:���������豸����ָ�����͵�ģ����ECC��Կ��
Args:	[in]	hSessionHandle:�Ự�����
		[in]    uiAlgID:ָ���㷨��ʶ
		[in]	  uiKeyBits:ָ����Կ����
		[out]   pucPublicKey��ECC��Կ�ṹ
		[out]   pucPrivateKey��ECC˽Կ�ṹ
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_GenerateKeyPair_ECC(void *hSessionHandle, unsigned int uiAlgID,unsigned int uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
/*=================================================================
Function: SDF_GenerateKeyWithIPK_ECC
Description:���ɻỰ��Կ����ָ���������ڲ����ܹ�ԿECC��Կ�������
Args:	[in]	hSessionHandle:�Ự�����
		[in]    uiIPKIndex�������豸�ڲ��洢��Կ������ֵ
		[in]	  uiKeyBits��ָ�������ĻỰ��Կ����
		[out]  	pucKey��������ָ�룬���ڴ�ŷ��ص���Կ����
		[out]  	phKeyHandle�����ص���Կ���
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle,unsigned int uiIPKIndex,unsigned int uiKeyBits,ECCCipher *pucKey,void **phKeyHandle);
/*=================================================================
Function:SDF_GenerateKeyWithEPK_ECC
Description:���ɻỰ��Կ�����ⲿECC��Կ�������
Args:	[in]	 hSessionHandle:�Ự�����
		[in]	 uiKeyBits��ָ�������ĻỰ��Կ����
		[in]    uiAlgID���ⲿECC��Կ���㷨��ʶ
	   [in]    pucPublicKey��������ⲿECC��Կ�ṹ
		[out]  	pucKey��������ָ�룬���ڴ�ŷ��ص���Կ����
		[out]	  phKeyHandle�����ص���Կ���
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle,unsigned int uiKeyBits,unsigned int uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucKey,void **phKeyHandle);
/*=================================================================
Function:SDF_ImportKeyWithISK_ECC
Description:����Ự��Կ�����ڲ�ECC˽Կ����
Args:	[in]	hSessionHandle:�Ự�����
		[in]	uiISKIndex�������豸�ڲ��洢����˽Կ������ֵ����Ӧ�ڼ���ʱ�Ĺ�Կ
		[in]   pucKey��������ָ�룬���ڴ�ŷ��ص���Կ����
		[out]	 phKeyHandle�����ص���Կ���
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_ImportKeyWithISK_ECC(void *hSessionHandle,unsigned int uiISKIndex,ECCCipher *pucKey,void **phKeyHandle);
/*=================================================================
Function: SDF_GenerateAgreementDataWithECC
Description:ʹ��ECC��ԿЭ���㷨��Ϊ����Ự��Կ������Э�̲�����ͬʱ����ָ������λ�õ�ECC��Կ����ʱECC��Կ�Ե�
��Կ�Լ�Э�̾����
Args:	[in]	hSessionHandle:�Ự�����
[in]	uiISKIndex:�����豸�ڲ��洢����˽Կ������ֵ����˽Կ������ԿЭ��
[in]    uiKeyBits��Ҫ��Э�̵���Կ����
[in]  	pucSponsorID��������ԿЭ�̵ķ���IDֵ
[in]   pucSponsorIDLength :������ԿЭ�̵ķ���ID����
[out]	pucSelfPublicKey�����صķ���ECC��Կ�ṹ
[out]	pucSelfTmpPublicKey�����صķ�����ʱECC��Կ�ṹ
[out]	phAgreementHandle�����ص�Э����Կ��������ڼ���Э����Կ
Return:��ȷ����SDR_OK�����󷵻ش�����룻
��ע��ΪЭ�̻Ự��Կ��Э�̵ķ���Ӧ���ȵ��ñ�����
==========================================================*/
int SDF_GenerateAgreementDataWithECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, void **phAgreementHandle);
/*=================================================================
Function: SDF_GenerateKeyWithECC
Description:ʹ��ECC��ԿЭ���㷨��ʹ������Э�̾������Ӧ����Э�̲�������Ự��Կ��ͬʱ���ػỰ��Կ�����
Args:	[in]	hSessionHandle:�Ự�����
[in]	pucResponseID:�ⲿ�������Ӧ��IDֵ
[in]    uiResponseIDLength���ⲿ�������Ӧ��ID����
[in]  	pucResponsePublicKey���ⲿ�������Ӧ��ECC��Կ�ṹ
[in]    pucResponseTmpPublicKey :�ⲿ�������Ӧ����ʱECC��Կ�ṹ
[in]	phAgreementHandle��Э����Կ��������ڼ���Э����Կ
[out]	phKeyHandle�����ص���Կ���
Return:��ȷ����SDR_OK�����󷵻ش�����룻
��ע��Э�̵ķ��𷽻����Ӧ����Э�̲�������ñ�����������Ự��Կ��ʹ��SM2�㷨�����ػ���Կ�Ĺ��̼�GM/T0009
==========================================================*/
int SDF_GenerateKeyWithECC(void *hSessionHandle, unsigned char *pucResponseID, unsigned int uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey, void *phAgreementHandle, void **phKeyHandle);
/*=================================================================
Function: SDF_GenerateAgreementDataWithECC
Description:ʹ��ECC��ԿЭ���㷨��Ϊ����Ự��Կ������Э�̲�����ͬʱ����ָ������λ�õ�ECC��Կ����ʱECC��Կ�Ե�
��Կ�Լ�Э�̾����
Args:	[in]	hSessionHandle:�Ự�����
[in]	uiISKIndex:�����豸�ڲ��洢����˽Կ������ֵ����˽Կ������ԿЭ��
[in]    uiKeyBits��Э�̺�Ҫ���������Կ����
[in]  	pucResponseID����Ӧ��IDֵ
[in]    uiResponseIDLength :��Ӧ��ID����
[in]  	pucSponsorID������IDֵ
[in]    uiSponsorIDLength :����ID����
[in]	pucSponsorPublicKey���ⲿ����ķ���ECC��Կ�ṹ
[in]	pucSponsorTmpPublicKey���ⲿ����ķ�����ʱECC��Կ�ṹ
[out]	pucResponsePublicKey�����ص���Ӧ��ECC��Կ�ṹ
[out]	pucResponseTmpPublicKey�����ص���Ӧ����ʱECC��Կ�ṹ
[out]	phKeyHandle�����ص���Կ���
Return:��ȷ����SDR_OK�����󷵻ش�����룻
��ע��ΪЭ�̻Ự��Կ��Э�̵ķ���Ӧ���ȵ��ñ�����
==========================================================*/
int SDF_GenerateAgreementDataAndKeyWithECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucResponseID, unsigned int uiResponseIDLength, unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, void **phKeyHandle);
/*=================================================================
Function: SDF_ExchangeDigitEnvelopeBaseOnECC
Description:�����ڲ����ܹ�Կ���ܵĻỰ��Կת��Ϊ���ⲿָ���Ĺ�Կ���ܣ������������ŷ�װ����
Args:	[in]	hSessionHandle:�Ự�����
[in]	uiKeyIndex:�����豸�ڲ��洢��Կ������Կ������ֵ
[in]    uiAlgID���ⲿECC��Կ���㷨��ʶ
[in]    pucPublicKey :�ⲿECC��Կ�ṹ
[in]	pucEncDateIn��������ָ�룬���ڴ������ĻỰ��Կ����
[out]	pucEncDateOut��������ָ�룬���ڴ������ĻỰ��Կ����
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_ExchangeDigitEnvelopeBaseOnECC(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDateIn, ECCCipher *pucEncDateOut);
/*=================================================================
Function: SDF_GenerateKeyWithKEK
Description:���ɻỰ��Կ������Կ������Կ�����ͬʱ������Կ���
Args:	[in]	hSessionHandle:�Ự�����
		[in]	uiKeyBits:ָ�������ĻỰ��Կ����
		[in]    uiAlgID���㷨��ʶ��ָ���ԳƼ����㷨
		[in]  	uiKEKIndex�������豸�ڲ��洢��Կ������Կ������ֵ
		[out]   pucKey :������ָ�룬���ڴ�ŷ��ص���Կ����
		[out]	puiKeyLength�����ص���Կ���ĳ���
		[out]	phKeyHandle�����ص���Կ���
��ע������ģʽʹ��ECB����ģʽ
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_GenerateKeyWithKEK(void *hSessionHandle,unsigned int uiKeyBits,unsigned int uiAlgID,unsigned int uiKEKIndex,unsigned char  *pucKey,unsigned int *puiKeyLength,void **phKeyHandle);
/*=================================================================
Function:SDF_ImportKeyWithKEK
Description:����Ự��Կ������Կ������Կ���ܣ�ͬʱ���ػỰ��Կ���
Args:	[in]	hSessionHandle:�Ự�����
		[in]    uiAlgID���㷨��ʶ��ָ���ԳƼ����㷨
		[in]  	uiKEKIndex�������豸�ڲ��洢��Կ������Կ������ֵ
		[in]    pucKey :������ָ�룬���ڴ�ŷ��ص���Կ����
		[in]	puiKeyLength�����ص���Կ���ĳ���
		[out]	phKeyHandle�����ص���Կ���
��ע������ģʽʹ��ECB����ģʽ
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_ImportKeyWithKEK(void *hSessionHandle,unsigned int uiAlgID,unsigned int uiKEKIndex,unsigned char  *pucKey,unsigned int puiKeyLength,void **phKeyHandle);

/*=================================================================================
Function: SDF_Importkey
Description:�������ĻỰ��Կ��ͬʱ������Կ���
Args:	[in]	hSessionHandle:�Ự�����
		[in]	puckey��������ָ�룬���ڴ���������Կ����
		[in]    puckey��������ָ�룬���ڴ���ⲿ���������
		[in]    puiKeyLength����������ݳ���
		[out]   phKeyHandle�����ص���Կ���		
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_ImportKey(void *hSessionHandle,unsigned char *pucKey,unsigned int puiKeyLength,void **phKeyHandle);

/*=================================================================================
Function: SDF_DestroyKey
Description:������Կ���ͷ�Ϊ��Կ���������ڴ����Դ��
Args:	[in]	hSessionHandle:�Ự�����
		[in]	phKeyHandle:��Կ���		
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_DestroyKey(void  *hSessionHandle,void *phKeyHandle);


/*=================================================================================
Function: SDF_ExternalVerify_ECC
Description:ʹ���ⲿECC��Կ��ECCǩ��ֵ������֤����
Args:	[in]	hSessionHandle:�Ự�����
		[in]	uiAlgID���㷨��ʶ��ָ��ʹ�õ�ECC�㷨
		[in]	pucPublicKey���ⲿECC��Կ�ṹ
		[in]  pucDataInput��������ָ�룬���ڴ���ⲿ���������
		[in]    uiInputLength����������ݳ���
		[in]    pucSignature��������ָ�룬���ڴ�������ǩ��ֵ����
��ע�����������Ϊ��ǩ���ݵ��Ӵ�ֵ����ʹ��SM2�㷨ʱ������������Ϊ��ǩ���ݾ���SM2ǩ��Ԥ����Ľ��		
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_ExternalVerify_ECC(void  *hSessionHandle,unsigned int uiAlgID,ECCrefPublicKey *pucPublicKey,unsigned char *pucDataInput,unsigned int uiInputLength,ECCSignature *pucSignature);
/*=================================================================================
Function: SDF_InternalSign_ECC
Description:ʹ���ڲ�ECC˽Կ�����ݽ���ǩ������
Args:	[in]	hSessionHandle:�Ự�����
		[in]	uiISKIndex�������豸�ڲ��洢��ECCǩ��˽Կ������ֵ
		[in]	pucData��������ָ�룬���ڴ���ⲿ��������ݣ���������Ϊ��ǩ���ݵ��Ӵ�ֵ��
		[in]    uiDataLength:��������ݳ���
		[out]   pucSignature��������ָ�룬���ڴ�������ǩ��ֵ������
��ע�����������Ϊ��ǩ���ݵ��Ӵ�ֵ����ʹ��SM2�㷨ʱ������������Ϊ��ǩ���ݾ���SM2ǩ��Ԥ����Ľ��
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_InternalSign_ECC(void  *hSessionHandle,unsigned int uiISKIndex,unsigned char *pucData,unsigned int uiDataLength,ECCSignature *pucSignature);
/*=================================================================================
Function: SDF_InternalVerify_ECC
Description:ʹ���ڲ�ECC��Կ��ECCǩ��ֵ������֤����
Args:	[in]	hSessionHandle:�Ự�����
		[in]	uiISKIndex�������豸�ڲ��洢��ECCǩ����Կ������ֵ
		[in]	pucData��������ָ�룬���ڴ���ⲿ��������ݣ���������Ϊ��ǩ���ݵ��Ӵ�ֵ��
		[in]    uiDataLength:��������ݳ���
		[in]    pucSignature��������ָ�룬���ڴ�������ǩ��ֵ����
��ע�����������Ϊ��ǩ���ݵ��Ӵ�ֵ����ʹ��SM2�㷨ʱ������������Ϊ��ǩ���ݾ���SM2ǩ��Ԥ����Ľ��
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_InternalVerify_ECC(void  *hSessionHandle,unsigned int uiISKIndex,unsigned char *pucData,unsigned int uiDataLength,ECCSignature *pucSignature);
/*=================================================================================
Function: SDF_ExternalSign_ECC
Description:ʹ���ⲿECC˽Կ�����ݽ���ǩ������
Args:	[in]	hSessionHandle:�Ự�����
		[in]	uiAlgID���㷨��ʶ��ָ��ʹ�õ�ECC�㷨
		[in]	pucPrivateKey���ⲿECC˽Կ�ṹ
		[in]  	pucDataInput��������ָ�룬���ڴ���ⲿ���������
		[in]    uiInputLength����������ݳ���
		[in]    pucSignature��������ָ�룬���ڴ�������ǩ��ֵ����
��ע�����������Ϊ��ǩ���ݵ��Ӵ�ֵ����ʹ��SM2�㷨ʱ������������Ϊ��ǩ���ݾ���SM2ǩ��Ԥ����Ľ��		
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_ExternalSign_ECC(void  *hSessionHandle,unsigned int uiAlgID,ECCrefPrivateKey *pucPrivateKey,unsigned char *pucDataInput,unsigned int uiInputLength,ECCSignature *pucSignature);

/*=================================================================================
Function: SDF_ExternalEncrypt_ECC
Description:ʹ���ⲿECC��Կ�����ݽ��м�������
Args:	[in]	hSessionHandle:�Ự�����
		[in]	uiAlgID���㷨��ʶ��ָ��ʹ�õ�ECC�㷨
		[in]	pucPublicKey���ⲿECC��Կ�ṹ
		[in]    pucData��������ָ�룬���ڴ���ⲿ���������
		[in]    uiDataLength����������ݳ���
		[out]   pucEncData��������ָ�룬���ڴ���������������		
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_ExternalEncrypt_ECC(void  *hSessionHandle,unsigned int uiAlgID,ECCrefPublicKey *pucPublicKey,unsigned char *pucData,unsigned int uiDataLength,ECCCipher *pucEncData);
/*=================================================================================
Function: SDF_ExternalDecrypt_ECC
Description:ʹ���ⲿECC˽Կ�����ݽ��н�������
Args:	[in]	hSessionHandle:�Ự�����
		[in]	uiAlgID���㷨��ʶ��ָ��ʹ�õ�ECC�㷨
		[in]	pucPrivateKey���ⲿECC˽Կ�ṹ
		[in]    pucEncData��������ָ�룬���ڴ���ⲿ���������
		[out]    pucData����������ݳ���
		[out]   puiDataLength��������ָ�룬���ڴ���������������		
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDF_ExternalDecrypt_ECC(void  *hSessionHandle,unsigned int uiAlgID,ECCrefPrivateKey *pucPrivateKey,ECCCipher *pucEncData,unsigned char* pucData,unsigned int *puiDataLength);

/*=================================================================================
Function: SDFEI_HashUpdateEnd
Description:�Ӵ����㶨�ƽӿڣ�����������Ľ����Ӵ����������������㲻����
Args:	[in]	hSessionHandle:�Ự�����
		[in]    pucData��������ָ�����ڴ���������������
	    [in]    uiDataLength��������������ĳ���
	   	[out]   pucHash��������ָ�룬���ڴ��������Ӵ�����
	    [out]   puiHashLength�����ص��Ӵ����ݳ���
Return:��ȷ����SDR_OK�����󷵻ش�����룻
=================================================================================*/
int SDFEI_HashUpdateEnd(void *hSessionHandle,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucHash,unsigned int *puiHashLength);

//HMAC�����ຯ��
/*=================================================================================
Function: SDFEI_HmacInit
Description:����ʽ����HMAC�����һ��
Args:	[in]	hSessionHandle:�Ự�����
		[in]	phKeyHandle����Կ���
Return:��ȷ����SDR_OK�����󷵻ش�����룻
==========================================================*/
int SDFEI_HmacInit(void *hSessionHandle,void *phKeyHandle);

/*=================================================================================
Function: SDFEI_HmacUpdate
Description:����ʽ����HMAC����ڶ���������������Ľ����Ӵ�����
Args:	[in]	hSessionHandle:�Ự�����
		[in]    pucData��������ָ�����ڴ���������������
	   [in]    uiDataLength��������������ĳ���
Return:��ȷ����SDR_OK�����󷵻ش�����룻
=================================================================================*/
int SDFEI_HmacUpdate(void *hSessionHandle,unsigned char *pucData,unsigned int uiDataLength);

/*=================================================================================
Function: SDFEI_HmacFinal
Description:����ʽ����HMAC������������Ӵ�������������Ӵ����ݲ�����м�����
Args:	[in]	hSessionHandle:�Ự�����
		[out]   pucHash��������ָ�룬���ڴ��������Ӵ�����
	   [out]   uiHashLength�����ص��Ӵ����ݳ���
Return:��ȷ����SDR_OK�����󷵻ش�����룻
=================================================================================*/
int SDFEI_HmacFinal(void  *hSessionHandle,unsigned char *pucData,unsigned int *puiHashLength);

/*=================================================================================
Function: SDFEI_HkdfExtract
Description:��Կ�������
Args:	[in]	hSessionHandle:�Ự�����
		[in]	phKeyHandle����Կ���
		[in]    pucData��������ָ�����ڴ���������������
	    [in]    uiDataLength��������������ĳ���  ���7K�ֽ�
	    [out]	phKeyOutHandle����Կ���
Return:��ȷ����SDR_OK�����󷵻ش�����룻
=================================================================================*/
int SDFEI_HkdfExtract(void *hSessionHandle,void *phKeyHandle,unsigned char *pucData,unsigned int uiDataLength,void **phKeyOutHandle);

#if 0
#define RSAref_MAX_BITS               2048
#define RSAref_MAX_LEN                ((RSAref_MAX_BITS + 7)/8)
#define RSAref_MAX_PBITS              ((RSAref_MAX_BITS + 1)/2)
#define RSAref_MAX_PLEN               ((RSAref_MAX_PBITS + 7)/8)



// SecretKey Manager
// RSA ��Կ�ṹ
typedef struct RSArefPublicKey_st {
	unsigned int  bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

// RSA ˽Կ�ṹ
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
*  �������������������豸�ڲ��洢��ָ��������ǩ����Կ
*  ������ hSessionHandle��in�� �Ѿ����豸���
*         uiKeyIndex[in]     �����豸�洢˽Կ����
*         pucPublicKey[out]  RSA��Կ�ṹ
*  ����ֵ��0  �ɹ��� ��0  ʧ�ܣ����ش������
*  ��ע�� ����׼�漰�����豸�洢����Կ������ֵ�ĵ���ʼ����ֵΪ�������Ϊ �� �������豸��ʵ �ʴ洢�������� �� ֵ
**/

int SDF_ExportSignPublicKey_RSA(void* hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey* pucPublicKey);
/**  6.3.2
*  �������������������豸�ڲ��洢��ָ�������ļ��ܹ�Կ
*  ������ hSessionHandle��in�� �Ѿ����豸���
*         uiKeyIndex[in]     �����豸�洢˽Կ����
*         pucPublicKey[out]  RSA��Կ�ṹ
*  ����ֵ��0  �ɹ��� ��0  ʧ�ܣ����ش������
*
**/

int SDF_ExportEncPublicKey_RSA(void* hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey* pucPublicKey);

/**  6.3.3
*  �������������������豸����ָ��ģ����RSA��Կ��
*  ������ hSessionHandle��in�� �Ѿ����豸���
*         uiKeyBits��in��      ָ����Կģ��
*         pucPublicKey[out]    RSA��Կ�ṹ
*         pucPrivateKey[out]   RSA˽Կ�ṹ
*  ����ֵ��0  �ɹ��� ��0  ʧ�ܣ����ش������
*
**/

int SDF_GenerateKeyPair_RSA(void* hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey* pucPublicKey, RSArefPrivateKey* pucPrivateKey);


/**   6.3.4
*  �������������ɻỰ��Կ�����ڲ�RSA��Կ�������
*  ������ hSessionHandle��in�� �Ѿ����豸���
*         uiPKIndex��in��      �����豸�ڲ��洢��Կ����
*         uiKeyBits��in��      ָ�������Ự��Կ����
*         pucKey[out]          ������ָ�룬���ڴ�ŷ��ص���Կ����
*         puiKeyLength[out]    ���ص���Կ���ĳ���
*         phKeyHandle[out]     ���ص���Կ���
*  ����ֵ��0  �ɹ��� ��0  ʧ�ܣ����ش������
*  ��ע�� ��Կ��������ʱ��䷽ʽ���գУˣãӣ����� ���� ����Ҫ�����
**/

int SDF_GenerateKeyWithIPK_RSA(void* hSessionHandle, unsigned int uiPKIndex, unsigned int uiKeyBits, unsigned char* pucKey, unsigned int* puiKeyLength, void** phKeyHandle);


/**   6.3.5
*  �������������ɻỰ��Կ�����ⲿRSA��Կ�������
*  ������ hSessionHandle��in�� �Ѿ����豸���
*         uiKeyBits��in��      ָ�������Ự��Կ����
*         pucPublicKey��in��   ������ⲿRSA��Կ�ṹ
*         pucKey[out]          ������ָ�룬���ڴ�ŷ��ص���Կ����
*         puiKeyLength[out]    ���ص���Կ���ĳ���
*         phKeyHandle[out]     ���ص���Կ���
*  ����ֵ��0  �ɹ��� ��0  ʧ�ܣ����ش������
*  ��ע�� ��Կ��������ʱ��䷽ʽ���գУˣãӣ����� ���� ����Ҫ�����
**/

int SDF_GenerateKeyWithEPK_RSA(void* hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey* pucPublicKey, unsigned char* pucKey, unsigned int* puiKeyLength, void** phKeyHandle);


/**  6.3.6
*  ��������������Ự��Կ�����ڲ�RSA˽Կ����
*  ������ hSessionHandle��in�� �Ѿ����豸���
*         uiISKIndex��in��     �����豸�ڲ��洢����˽Կ������ֵ����Ӧ�ڼ���ʱ��Ĺ�Կ
*         pucKey[in]          ������ָ�룬���ڴ�ŷ��ص���Կ����
*         puiKeyLength[in]    ���ص���Կ���ĳ���
*         phKeyHandle[out]     ���ص���Կ���
*  ����ֵ��0  �ɹ��� ��0  ʧ�ܣ����ش������
*  ��ע�� ��Կ��������ʱ��䷽ʽ���գУˣãӣ����� ���� ����Ҫ�����
**/

int SDF_ImportKeyWithISK_RSA(void* hSessionHandle, unsigned int uiISKeyIndex, unsigned char* pucKey, unsigned int puiKeyLength, void** phKeyHandle);

/**   6.3.7
*  ���������������ڲ����ܹ�Կ���ܵĻỰ��Կת��Ϊ��ָ���ⲿ��Կ���ܣ������������ŷ�ת��
*  ������ hSessionHandle��in�� �Ѿ����豸�Ự���
*         uiKeyIndex��in��     �����豸�ڲ��洢��RSA��Կ������ֵ
*         pucPublicKey[in]     �ⲿRSA��Կ�ṹ
*         pucDEInput[in]       ������ָ�룬���ڴ������ĻỰ��Կ����
*         uiDELength[in]       ����ĻỰ��Կ���ĳ���
*         pucDEOutput[out]     ������ָ�룬���ڴ�������ת����ĻỰ��Կ����
*         puiDELength[out]     ����ת����ĻỰ��Կ���ĳ���
*  ����ֵ��0  �ɹ��� ��0  ʧ�ܣ����ش������
*  ��ע�� ��Կ��������ʱ��䷽ʽ���գУˣãӣ����� ���� ����Ҫ�����
**/

int SDF_ExchangeDigitEnvelopeBaseOnRSA(void* hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey* pucPublicKey, unsigned char* pucDEInput, unsigned int uiDELength, unsigned char* pucDEOutput, unsigned int* puiDELength);


/**   6.4.1
*  ����������ָ��ʹ���ⲿ��Կ�����ݽ�������
*  ������ hSessionHandle��in��      ���豸�����ĻỰ���
*         pucPublicKey[in]          �ⲿRSA��Կ�ṹ
*         pucDataInput[in]          ������ָ�룬���ڴ�����������
*         uiInputLength[in]         �������ݳ���
*         pucDataOutput[out]        ������ָ�룬���ڴ�����������
*         puiOutputLength[out]      ������ݳ���
*  ����ֵ��0  �ɹ��� ��0  ʧ�ܣ����ش������
*  ��ע�� ���ݸ�ʽ��Ӧ�ò��װ
**/

int SDF_ExternalPublicKeyOperation_RSA(void* hSessionHandle, RSArefPublicKey* pucPublicKey, unsigned char* pucDataInput, unsigned int uiInputLength, unsigned char* pucDataOutput, unsigned int* puiOutputLength);

/**   6.4.2
*  ����������ָ��ʹ���ⲿ˽Կ�����ݽ�������
*  ������ hSessionHandle��in��      ���豸�����ĻỰ���
*         pucPrivateKey[in]         �ⲿRSA˽Կ�ṹ
*         pucDataInput[in]          ������ָ�룬���ڴ�����������
*         uiInputLength[in]         �������ݳ���
*         pucDataOutput[out]        ������ָ�룬���ڴ�����������
*         puiOutputLength[out]      ������ݳ���
*  ����ֵ��0  �ɹ��� ��0  ʧ�ܣ����ش������
*  ��ע�� ���ݸ�ʽ��Ӧ�ò��װ
**/

int SDF_ExternalPrivateKeyOperation_RSA(void* hSessionHandle, RSArefPrivateKey* pucPrivateKey, unsigned char* pucDataInput, unsigned int uiInputLength, unsigned char* pucDataOutput, unsigned int* puiOutputLength);

/**   6.4.3
*  ����������ָ��ʹ���ڲ���Կ�����ݽ�������
*  ������ hSessionHandle��in��      ���豸�����ĻỰ���
*         uiKeyIndex[in]            �����豸�ڲ��洢��Կ������ֵ
*         pucDataInput[in]          ������ָ�룬���ڴ�����������
*         uiInputLength[in]         �������ݳ���
*         pucDataOutput[out]        ������ָ�룬���ڴ�����������
*         puiOutputLength[out]      ������ݳ���
*  ����ֵ��0  �ɹ��� ��0  ʧ�ܣ����ش������
*  ��ע��  ������Χ�������ڲ�ǩ����Կ�ԣ����ݸ�ʽ��Ӧ�ò��װ
**/

int SDF_InternalPublicKeyOperation_RSA(void* hSessionHandle, unsigned int uiKeyIndex, unsigned char* pucDataInput, unsigned int uiInputLength, unsigned char* pucDataOutput, unsigned int* puiOutputLength);

/**   6.4.4
*  ����������ָ��ʹ���ڲ�ָ��������˽Կ�����ݽ�������
*  ������ hSessionHandle��in��      ���豸�����ĻỰ���
*         uiKeyIndex[in]            �����豸�ڲ��洢˽Կ������ֵ
*         pucDataInput[in]          ������ָ�룬���ڴ�����������
*         uiInputLength[in]         �������ݳ���
*         pucDataOutput[out]        ������ָ�룬���ڴ�����������
*         puiOutputLength[out]      ������ݳ���
*  ����ֵ��0  �ɹ��� ��0  ʧ�ܣ����ش������
*  ��ע��  ������Χ�������ڲ�ǩ����Կ�ԣ����ݸ�ʽ��Ӧ�ò��װ
**/

int SDF_InternalPrivateKeyOperation_RSA(void* hSessionHandle, unsigned int uiKeyIndex, unsigned char* pucDataInput, unsigned int uiInputLength, unsigned char* pucDataOutput, unsigned int* puiOutputLength);

#endif





//C++ End
#ifdef __cplusplus
}
#endif



#endif	//_HSM_SDK_H_


