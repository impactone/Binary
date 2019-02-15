#include "Driver_ENCODER.h"

MotorMsgType MotorMsg;

void MotorMsg_InitConfig(void)
{
	MotorMsg.Current     = 0;
	MotorMsg.Encoder.Pos = 0;
	MotorMsg.Encoder.Vol = 0;
}

void Control_task(void)
{
	int16_t pwm = 0;

	MotorMsg.Encoder.Pos += 30000 - TIM3->CNT;	
	MotorMsg.Encoder.Vol  = 30000 - TIM3->CNT ;
	TIM3->CNT = 30000;
	
	PID_Motor_P.Measured = MotorMsg.Encoder.Pos;
	PID_Motor_V.Measured = MotorMsg.Encoder.Vol;

	//位置-速度环
	PID_Motor_P.Expect   = exp_pos;
	PID_Motor_V.Expect   = PID_Calc(&PID_Motor_P);
	pwm                  = PID_Calc(&PID_Motor_V);
	
	//输出
	SetMotorPWM(pwm);
}
