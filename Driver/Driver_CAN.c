#include "Driver_CAN.h"

RecMsgType RecMsg = {0,120};
int exp_pos = 0;
u8 can_num = 0;
void CAN1_Process(void)
{
	CanRxMsg RxMsg;
	CAN_Receive(CAN1,CAN_FIFO0,&RxMsg);
	if (RxMsg.StdId == CAN_REC_ID)
	{
		if(can_num == 0)
		{
			can_num = 1;
			RecMsg.CAN1_Msg = (u8)RxMsg.Data[0];
			RecMsg.MAX_VOL = (u8)RxMsg.Data[1];
		}
	}

}
