    
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hsm_sdk.h>
int main(){

    int ret = 0;
	void *DevcieHandle = NULL;
	void *SessionHandle = NULL;
	
	ret = SDF_OpenDevice(&DevcieHandle);
	if(ret)
	{
		printf("SDF_OpenDevice failed:%x\n", ret);
		return ret;
	}

	ret = SDF_OpenSession(DevcieHandle, &SessionHandle);
	if(ret)
	{
		printf("SDF_OpenSession failed:%x\n", ret);
		return ret;
	}
    
}