#include "Driver_ADC.h"

uint16_t Get_ADC_Value(void)
{
	ADC_RegularChannelConfig(ADC1, ADC_Channel_0, 1, ADC_SampleTime_239Cycles5 );		  			   
	ADC_SoftwareStartConvCmd(ADC1, ENABLE);			 
	while(!ADC_GetFlagStatus(ADC1, ADC_FLAG_EOC )) {};//等待转换结束

  return ADC_GetConversionValue(ADC1);	//返回最近一次ADC1规则组的转换结果
}

/*确定电流零点*/
float CurrentZeroPoint;
void CurrentZeroPointConfirm(void)
{
	uint8_t i;
	float sum = 0;
	for (i = 0; i < 100;i++)
	{
		sum += Get_ADC_Value() * 0.001343f;
	}
	
	CurrentZeroPoint = sum / 100.0f;
	
}

/*电流均值滤波*/
float CurrentFitlter(float current)
{
	static float current_buff[5] = {0};
	float sum = 0;
	uint8_t i;
	
	for ( i = 0;i < 3;i++)
	{
		current_buff[i] = current_buff[i+1];
	}
	current_buff[3] = current;
	
	for ( i = 0;i < 4;i++)
	{
		sum += current_buff[i];
	}
	
	return sum / 4.0f;
	
}

/*
	mode 取1 返回adc采样结果
			 取2 返回实际电流值 单位：毫安
*/
float Get_Current(uint8_t mode)
{
	float tmp;

	tmp = Get_ADC_Value() * 0.001343f;	
	
	if (mode)
	{
		tmp = (CurrentFitlter(tmp) - CurrentZeroPoint) / 0.1f;
		return tmp;
	}
	
	return (float)tmp;
}



