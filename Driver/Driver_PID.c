#include "Driver_PID.h"

POS_PID_Struct PID_Motor_P;  //位置环
POS_PID_Struct PID_Motor_V;  //速度环


/*PID结构体初始化*/
void PIDStruct_Init(POS_PID_Struct *pid)
{
	
	pid->P          = 0;
	pid->I          = 0;
	pid->D          = 0;
	pid->Imax       = 0;
	pid->NowErr     = 0;
	pid->LstErr     = 0;
	pid->SumErr     = 0;
	pid->Expect     = 0;
	pid->Measured   = 0;
	pid->OutPut     = 0;
	pid->MaxOutput  = 0;
}

/*PID参数初始化*/
void PID_Param_Init(POS_PID_Struct *pid,\
	                  float p,float i,float d,\
										float im,float output)
{
	pid->P          = p;
	pid->I          = i;
	pid->D          = d;
	pid->Imax       = im;
	pid->MaxOutput  = output;
}

void PID_InitConfig(void)
{
	PIDStruct_Init(&PID_Motor_P);
	PIDStruct_Init(&PID_Motor_V);
	
	//位置-速度环
	//调完了0.06,0,1.33	//6.5,1.1,0
	PID_Param_Init(&PID_Motor_P,0.06,0.0,1.33,5000,100); 
	PID_Param_Init(&PID_Motor_V,6.5,1.1,0.0,10000,4900);
}


/*PID计算函数*/
float PID_Calc(POS_PID_Struct *pid)
{
	float Pout = 0,Iout = 0,Dout = 0;
	
	/*误差计算*/
	pid->NowErr  = pid->Expect - pid->Measured;
	pid->SumErr += (pid->I == 0) ? 0 : pid->NowErr;
	
	/*P-I-D*/
	Pout = pid->P * pid->NowErr;
	Iout = pid->I * pid->SumErr;
	Dout = pid->D * (pid->NowErr - pid->LstErr);
	
	/*积分限幅*/
	if (Iout >= pid->Imax)
	{
		pid->SumErr -= pid->NowErr; 
		Iout        = pid->Imax;
	}
	else if (Iout <= -pid->Imax)
	{
		pid->SumErr -= pid->NowErr;
		Iout        = -pid->Imax;
	}
	
	/*PID输出*/
	pid->OutPut = Pout + Iout + Dout;
	
	/*输出限幅*/
	if (pid->OutPut >= pid->MaxOutput) 
		pid->OutPut = pid->MaxOutput;
	else if (pid->OutPut <= -pid->MaxOutput)
	  pid->OutPut = -pid->MaxOutput;
	
	/*误差更新*/
	pid->LstErr = pid->NowErr;
		
	return pid->OutPut;
}








