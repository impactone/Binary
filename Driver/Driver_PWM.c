#include "Driver_PWM.h"

/*
	pwm·¶Î§Îª0-5000
*/

void SetMotorPWM(int16_t pwm)
{
	if (pwm >= 4900)
	{
		pwm = 4900;
	}else if (pwm <= -4900)
	{
		pwm = -4900;
	}
	
	if (pwm > 0)
	{
		TIM1->CCR2 = 0;
		TIM1->CCR3 = pwm;
	}else
	{
		TIM1->CCR2 = -pwm;
		TIM1->CCR3 = 0;
	}
	
}
