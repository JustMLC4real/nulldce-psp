#pragma once
#include "aica.h"

void arm_Init();
void arm_Reset();	
void arm_Run(u32 uNumCycles);
void arm_SetEnabled(bool enabled);

#define arm_sh4_bias (2)

#define UpdateArm(Cycles) arm_Run(Cycles/arm_sh4_bias);



