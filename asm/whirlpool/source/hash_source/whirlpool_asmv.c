#include <stdlib.h>
#include <string.h>

#include "../include/whirlpool_asmv.h"

static const uint64_t cr_asmv[10] = {
	LE64(0x4f01b887e8c62318LLU), LE64(0x52916f79f5d2a636LLU),
	LE64(0x357b0ca38e9bbc60LLU), LE64(0x57fe4b2ec2d7e01dLLU),
	LE64(0xda4af09fe5377715LLU), LE64(0x856ba0b10a29c958LLU),
	LE64(0x67053ecbf4105dbdLLU), LE64(0xd8957da78b4127e4LLU),
	LE64(0x9e4717dd667ceefbLLU), LE64(0x33835aad07bf2dcaLLU)
};

static const uint8_t boxes[48] = {
	/* rbox */
	0x7, 0xC, 0xB, 0xD, 0xE, 0x4, 0x9, 0xF,
	0x6, 0x3, 0x8, 0xA, 0x2, 0x5, 0x1, 0x0,
	/* ebox */
	0x1, 0xB, 0x9, 0xC, 0xD, 0x6, 0xF, 0x3,
	0xE, 0x8, 0x7, 0x4, 0xA, 0x2, 0x5, 0x0,
	/* iebox */
	0xF, 0x0, 0xD, 0x7, 0xB, 0xE, 0x5, 0xA,
	0x9, 0x2, 0xC, 0x1, 0x3, 0x4, 0x8, 0x6,
};

static const uint8_t mix_r[8] = {0x01, 0x01, 0x04, 0x01, 0x08, 0x05, 0x02, 0x09};

static void
sub_bytes(uint64_t state[8])
{
	asm(
	    "vldm.64 %[a], {d0-d5}\n\t"           /* q0 = rbox, q1 = ebox,   */
	                                          /* q2 = iebox              */

	    "vmov.i8 q3, #0xF\n\t"                /* q3 = 0xF                */

	    "vldm.64 %[s], {d8-d15}\n\t"          /* State загружаем в       */
	                                          /* q4-q7                   */

	    "vshr.u8 q12, q4, #4\n\t"             /* i >> 4 в q12           */
	    "vand q13, q4, q3\n\t"                /* i & 0xF в q13          */

	    "vtbl.8 d24, {d2, d3}, d24\n\t"       /* в q12 содержится x,     */
	    "vtbl.8 d25, {d2, d3}, d25\n\t"       /* x = ebox[i >> 4]        */

	    "vtbl.8 d26, {d4, d5}, d26\n\t"       /* в q13 содержится y,     */
	    "vtbl.8 d27, {d4, d5}, d27\n\t"       /* y = iebox[i & 0xF]      */

	    "veor.8 q14, q12, q13\n\t"            /* q14 = x ^ y             */

	    "vtbl.8 d28, {d0, d1}, d28\n\t"       /* в  q14 содержится r,     */
	    "vtbl.8 d29, {d0, d1}, d29\n\t"       /* r = rbox[x ^ y]         */

	    "veor.8 q12, q14\n\t"                 /* x ^= r                  */
	    "veor.8 q13, q14\n\t"                 /* y ^= r                  */

	    "vtbl.8 d24, {d2, d3}, d24\n\t"
	    "vtbl.8 d25, {d2, d3}, d25\n\t"       /* в q12 содержится ebox[x]*/

	    "vshl.u8 q12, #4\n\t"                 /*  q12 = ebox[x] << 4     */

	    "vtbl.8 d26, {d4, d5}, d26\n\t"       /*  в q13 содержится iebox[y] */
	    "vtbl.8 d27, {d4, d5}, d27\n\t"       

	    "vorr.8 q4, q12, q13\n\t"             /* (ebox[x] << 4) |        */
	                                          /* iebox[y]                */

	                                          /* q5 итерация */
	    "vshr.u8 q12, q5, #4\n\t"
	    "vand q13, q5, q3\n\t"
	    "vtbl.8 d24, {d2, d3}, d24\n\t"
	    "vtbl.8 d25, {d2, d3}, d25\n\t"
	    "vtbl.8 d26, {d4, d5}, d26\n\t"
	    "vtbl.8 d27, {d4, d5}, d27\n\t"
	    "veor.8 q14, q12, q13\n\t"
	    "vtbl.8 d28, {d0, d1}, d28\n\t"
	    "vtbl.8 d29, {d0, d1}, d29\n\t"
	    "veor.8 q12, q14\n\t"
	    "veor.8 q13, q14\n\t"
	    "vtbl.8 d24, {d2, d3}, d24\n\t"
	    "vtbl.8 d25, {d2, d3}, d25\n\t"
	    "vshl.u8 q12, #4\n\t"
	    "vtbl.8 d26, {d4, d5}, d26\n\t"
	    "vtbl.8 d27, {d4, d5}, d27\n\t"
	    "vorr.8 q5, q12, q13\n\t"

	                                          /* q6 итерация */
	    "vshr.u8 q12, q6, #4\n\t"
	    "vand q13, q6, q3\n\t"
	    "vtbl.8 d24, {d2, d3}, d24\n\t"
	    "vtbl.8 d25, {d2, d3}, d25\n\t"
	    "vtbl.8 d26, {d4, d5}, d26\n\t"
	    "vtbl.8 d27, {d4, d5}, d27\n\t"
	    "veor.8 q14, q12, q13\n\t"
	    "vtbl.8 d28, {d0, d1}, d28\n\t"
	    "vtbl.8 d29, {d0, d1}, d29\n\t"
	    "veor.8 q12, q14\n\t"
	    "veor.8 q13, q14\n\t"
	    "vtbl.8 d24, {d2, d3}, d24\n\t"
	    "vtbl.8 d25, {d2, d3}, d25\n\t"
	    "vshl.u8 q12, #4\n\t"
	    "vtbl.8 d26, {d4, d5}, d26\n\t"
	    "vtbl.8 d27, {d4, d5}, d27\n\t"
	    "vorr.8 q6, q12, q13\n\t"

	                                          /* q7 итерация */
	    "vshr.u8 q12, q7, #4\n\t"
	    "vand q13, q7, q3\n\t"
	    "vtbl.8 d24, {d2, d3}, d24\n\t"
	    "vtbl.8 d25, {d2, d3}, d25\n\t"
	    "vtbl.8 d26, {d4, d5}, d26\n\t"
	    "vtbl.8 d27, {d4, d5}, d27\n\t"
	    "veor.8 q14, q12, q13\n\t"
	    "vtbl.8 d28, {d0, d1}, d28\n\t"
	    "vtbl.8 d29, {d0, d1}, d29\n\t"
	    "veor.8 q12, q14\n\t"
	    "veor.8 q13, q14\n\t"
	    "vtbl.8 d24, {d2, d3}, d24\n\t"
	    "vtbl.8 d25, {d2, d3}, d25\n\t"
	    "vshl.u8 q12, #4\n\t"
	    "vtbl.8 d26, {d4, d5}, d26\n\t"
	    "vtbl.8 d27, {d4, d5}, d27\n\t"
	    "vorr.8 q7, q12, q13\n\t"

	    "vstm.64 %[s], {q4-q7}\n\t"
	:
	: [s] "r" (state), [a] "r" (boxes)
	: "memory", "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q12",
	  "q13", "q14"
	);
}


static void
print_state(uint64_t state[8])
{
	printf("%016llX\n", state[0]);
	printf("%016llX\n", state[1]);
	printf("%016llX\n", state[2]);
	printf("%016llX\n", state[3]);
	printf("%016llX\n", state[4]);
	printf("%016llX\n", state[5]);
	printf("%016llX\n", state[6]);
	printf("%016llX\n", state[7]);
}

static void
mix_rows(uint64_t state[8])
{
	/* state это 64 байта s0, …, s64, расположеных в матричной форме::
	 *         [ s00 s01 s02 s03 s04 s05 s06 s07 ]
	 *         [ s10 s11 s12 s13 s14 s15 s16 s17 ]
	 *         [ s20 s21 s22 s23 s24 s25 s26 s27 ]
	 * state = [ s30 s31 s32 s33 s34 s35 s36 s37 ].
	 *         [ s40 s41 s42 s43 s44 s45 s46 s47 ]
	 *         [ s50 s51 s52 s53 s54 s55 s56 s57 ]
	 *         [ s60 s61 s62 s63 s64 s65 s66 s67 ]
	 *         [ s70 s71 s72 s73 s74 s75 s76 s77 ]
	  * Мы хотим умножить матрицу состояния на матрицу MDSGC в GF(2^8):
	 *         [ 0x1 0x1 0x4 0x1 0x8 0x5 0x2 0x9 ]
	 *         [ 0x9 0x1 0x1 0x4 0x1 0x8 0x5 0x2 ]
	 *         [ 0x2 0x9 0x1 0x1 0x4 0x1 0x8 0x5 ]
	 * MDSGC = [ 0x5 0x2 0x9 0x1 0x1 0x4 0x1 0x8 ].
	 *         [ 0x8 0x5 0x2 0x9 0x1 0x1 0x4 0x1 ]
	 *         [ 0x1 0x8 0x5 0x2 0x9 0x1 0x1 0x4 ]
	 *         [ 0x4 0x1 0x8 0x5 0x2 0x9 0x1 0x1 ]
	 *         [ 0x1 0x4 0x1 0x8 0x5 0x2 0x9 0x1 ]
	 * Мы получаем новое значение байта (tij), i = 0, …, 7, j = 0, …, 7.
	 * Рассмотрим 1 ряд новой матрицы состояния в транспонированной форме:
	 * [t00]   [s00 * 0x1]   [s01 * 0x9]       [s07 * 0x1]
	 * [t01]   [s00 * 0x1]   [s01 * 0x1]       [s07 * 0x4]
	 * [t02]   [s00 * 0x4]   [s01 * 0x1]       [s07 * 0x1]
	 * [t03] = [s00 * 0x1] ^ [s01 * 0x4] ^ … ^ [s07 * 0x8].
	 * [t04]   [s00 * 0x8]   [s01 * 0x1]       [s07 * 0x5]
	 * [t05]   [s00 * 0x5]   [s01 * 0x8]       [s07 * 0x2]
	 * [t06]   [s00 * 0x2]   [s01 * 0x5]       [s07 * 0x9]
	 * [t07]   [s00 * 0x9]   [s01 * 0x2]       [s07 * 0x1]
	 * Мы можем сделать следующую замену:
	 * [t00]   [s00]   [s05]   [s07]    [s02]    [s06]    [s03]    [s04]
	 * [t01]   [s01]   [s06]   [s00]    [s03]    [s07]    [s04]    [s05]
	 * [t02]   [s02]   [s07]   [s01]    [s04]    [s00]    [s05]    [s06]
	 * [t03] = [s03] ^ [s00] ^ [s02] ^ 2[s05] ^ 4[s01] ^ 5[s06] ^ 8[s07] ^
	 * [t04]   [s04]   [s01]   [s03]    [s06]    [s02]    [s07]    [s00]
	 * [t05]   [s05]   [s02]   [s04]    [s07]    [s03]    [s00]    [s01]
	 * [t06]   [s06]   [s03]   [s05]    [s00]    [s04]    [s01]    [s02]
	 * [t07]   [s07]   [s04]   [s06]    [s01]    [s05]    [s02]    [s03]
	 *
	 *          [s01]   [s00]   [s05]   [s07]   [s03]   [s01]
	 *          [s02]   [s01]   [s06]   [s00]   [s04]   [s02]
	 *          [s03]   [s02]   [s07]   [s01]   [s05]   [s03]
	 *       ^ 9[s04] = [s03] ^ [s00] ^ [s02] ^ [s06] ^ [s04] ^
	 *          [s05]   [s04]   [s01]   [s03]   [s07]   [s05]
	 *          [s06]   [s05]   [s02]   [s04]   [s00]   [s06]
	 *          [s07]   [s06]   [s03]   [s05]   [s01]   [s07]
	 *          [s00]   [s07]   [s04]   [s06]   [s02]   [s00]
	 *
	 *          [s02]    [s06]    [s03]    [s04]    [s01]
	 *          [s03]    [s07]    [s04]    [s05]    [s02]
	 *          [s04]    [s00]    [s05]    [s06]    [s03]
	 *       ^ 2[s05] ^ 4[s01] ^ 4[s06] ^ 8[s07] ^ 8[s04].
	 *          [s06]    [s02]    [s07]    [s00]    [s05]
	 *          [s07]    [s03]    [s00]    [s01]    [s06]
	 *          [s00]    [s04]    [s01]    [s02]    [s07]
	 *          [s01]    [s05]    [s02]    [s03]    [s00]
	 * Мы можем сделать это, используя 16-байтовые регистры для преобразования 2 строк,
	 * и команду vext для нахождения элемента в столбце.
	 *
	 */
	asm(
	    "mov r0, #8\n\t"                /* в r0 записываем количество строк  */
	    "mov r1, %[s]\n\t"

	    "vmov.i8 q14, #0x80\n\t"        /* Регистры необходимы для умножения */
	    "vmov.i8 q15, #0x1D\n\t"        /* на 2, 4, 8. Мы используем  	 */
	                                    /* q13 для vtst                 	 */

	    "mix_rows_loop_start:\n\t"

	    "subs r0, #2\n\t"               /* Мы обрабатываем 2 ряда сразу  	 */
	    "bmi mix_rows_loop_end\n\t"

	    "vldm.64 r1, {q0}\n\t"          /* в q0 хранятся текущие строки,  	 */
	                                    /* и будет записан результат 	 */
	                    
	    "vext.8 d2, d0, d0, #1\n\t"     /* q1 = [s01, …, s00, s11, …, s10]	 */
	    "vext.8 d3, d1, d1, #1\n\t"    
	    "veor.8 q0, q1\n\t"

	    "vext.8 d2, d2, #2\n\t"         /* q1 = s03, …, s02, s13, …, s12]    */
	    "vext.8 d3, d3, #2\n\t"        
	    "veor.8 q0, q1\n\t"

	    "vext.8 d2, d2, #2\n\t"         /* q1 = [s05, …, s04, s15, …, s14]   */     
	    "vext.8 d3, d3, #2\n\t"         
	    "veor.8 q0, q1\n\t"

	    "vext.8 d2, d2, #2\n\t"         /* q1 = [s07, …, s06, s17, …, s16]   */
	    "vext.8 d3, d3, #2\n\t"         
	    "veor.8 q0, q1\n\t"

	                                 /* Умножение на  2             	 */
	    "vtst.8 q13, q1, q14\n\t"    

	    "vand.i8 q13, q15\n\t"       /* каждый байт в q13 = 0x1D,если старший*/
	                                 /*  байт = 1 или 0x00, если байт = 0 	 */
	
	                                 
	    "vshl.u8 q1, #1\n\t"         /* Циклический сдвиг на 1 бит влево     */

	    "veor.i8 q1, q13\n\t"        /* q1 = 2 * [s07, …, s06, s17, …, s16]  */

	    "vext.8 d2, d2, #3\n\t"      /* q1 = 2 * [s02, …, s01, s12, …, s11]  */
	    "vext.8 d3, d3, #3\n\t"     
	    "veor.8 q0, q1\n\t"

	                                 /* Умножение на 4              	 */
	    "vtst.8 q13, q1, q14\n\t"
	    "vand.i8 q13, q15\n\t"
	    "vshl.u8 q1, #1\n\t"
	    "veor.i8 q1, q13\n\t"        /* q1 = 4 * [s02, …, s01, s12, …, s11]  */  

	    "vext.8 d2, d2, #1\n\t"      /* q1 = 4 * [s03, …, s02, s13, …, s12]  */  
	    "vext.8 d3, d3, #1\n\t"    
	    "veor.8 q0, q1\n\t"

	    "vext.8 d2, d2, #3\n\t"      /* q1 = 4 * [s06, …, s05, s16, …, s15]  */    
	    "vext.8 d3, d3, #3\n\t"     
	    "veor.8 q0, q1\n\t"

	                                 /* Умножение на 8             		 */
	    "vtst.8 q13, q1, q14\n\t"
	    "vand.i8 q13, q15\n\t"
	    "vshl.u8 q1, #1\n\t"
	    "veor.i8 q1, q13\n\t"        /* q1 = 8 * [s06, …, s05, s16, …, s15]  */ 
	                             
	    "vext.8 d2, d2, #3\n\t"      /* q1 = 8 * [s01, …, s00, s11, …, s00]  */ 
	    "vext.8 d3, d3, #3\n\t"    
	    "veor.8 q0, q1\n\t"

	    "vext.8 d2, d2, #3\n\t"      /* q1 =  8 * [s04, …, s03, s14, …, s03] */ 
	    "vext.8 d3, d3, #3\n\t"      
	    "veor.8 q0, q1\n\t"

	    "vstm.64 r1!, {q0}\n\t"

	    "b mix_rows_loop_start\n\t"

	    "mix_rows_loop_end:\n\t"
	    :
	    : [s] "r" (state)
	    : "memory", "r0", "r1", "q0", "q1", "q13", "q14", "q15"
	   );
}

static void
shift_columns(uint64_t state[8])
{
	asm volatile(
	    "mov r0, %[a]\n\t"
	    "vld4.8 {d0-d3}, [r0]!\n\t"   /* vld4.8 загружает первые 4 байта как   */
	    "vld4.8 {d4-d7}, [r0]\n\t"    /* первые элементы регистров в список,  */
	                                  /* вторые 4 байта как следующие элементы */
	                                  /* и т.д. Оригинальная матрица*/
	                                  /* загружается в d0-d7, и выглядит следующим образом     */
	                                  /* 00 04 08 0C 10 14 18 1C         */
	                                  /* 01 05 09 0D 11 15 19 1D         */
	                                  /* 02 06 0A 0E 12 16 1A 1E         */
	                                  /* 03 07 0B 0F 13 17 1B 1F         */
	                                  /* 20 24 28 2C 30 34 38 3C         */
	                                  /* 21 25 29 2D 31 35 39 3D         */
	                                  /* 22 26 2A 2E 32 36 3A 3E         */
	                                  /* 23 27 2B 2F 33 37 3B 3F         */

	    "vuzp.8 d0, d4\n\t"           /* vuzp.8 сдвигает байты в 2 регистрах*/
	    "vuzp.8 d1, d5\n\t"           /* Например,  */
	    "vuzp.8 d2, d6\n\t"           
	    "vuzp.8 d3, d7\n\t"           /* d0 = 00 04 08 0C 10 14 18 1C,   */
	                                  /* d4 = 20 24 28 2C 30 34 38 3C    */
	                                  /* после vuzp.8 d0, d4 мы получаем */
	                                  /* d0 = 00 08 10 18 20 28 30 38    */
	                                  /* d1 = 04 0C 14 1C 24 2C 34 3C.   */
	                                  /* Вызвав команду vuzp.8 4 раза,*/
	                                  /* получаем следующую матрицу */
	                                  /* 00 08 10 18 20 28 30 38         */
	                                  /* 01 09 11 19 21 29 31 39         */
	                                  /* 02 0A 12 1A 22 2A 32 3A         */
	                                  /* 03 0B 13 1B 23 2B 33 3B         */
	                                  /* 04 0C 14 1C 24 2C 34 3C         */
	                                  /* 05 0D 15 1D 25 2D 35 3D         */
	                                  /* 06 0E 16 1E 26 2E 36 3E         */
	                                  /* 07 0F 17 1F 27 2F 37 3F         */
	                                  /* Это транспонированая матрица/
	                                  /*  от оригинальной. Сейчас мы */
	                                  /* можем сдвигать строки, содержащиеся  */
	                                  /* в d0-d7 */

	    "vext.8 d1, d1, #7\n\t"       /* Выполняем циклический сдвиг строк*/
	    "vext.8 d2, d2, #6\n\t"      
	    "vext.8 d3, d3, #5\n\t"       
	    "vext.8 d4, d4, #4\n\t"       
	    "vext.8 d5, d5, #3\n\t"       
	    "vext.8 d6, d6, #2\n\t"       
	    "vext.8 d7, d7, #1\n\t"      

	    "vzip.8 d0, d4\n\t"           /* Транспонирование   */
	    "vzip.8 d1, d5\n\t"           
	    "vzip.8 d2, d6\n\t"           
	    "vzip.8 d3, d7\n\t"           
	    "mov r0, %[a]\n\t"           
	    "vst4.8 {d0-d3}, [r0]!\n\t"  
	    "vst4.8 {d4-d7}, [r0]\n\t"    
	                                  
	    :
	    : [a] "r" (state)
	    : "memory", "r0", "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"
	   );
}

static void
add_round_key(uint64_t state[8], uint64_t rk[8])
{
	asm(
	    "vldm.64 %[s], {d0-d7}\n\t"
	    "vldm.64 %[r], {d8-d15}\n\t"
	    "veor.8 q0, q4\n\t"
	    "veor.8 q1, q5\n\t"
	    "veor.8 q2, q6\n\t"
	    "veor.8 q3, q7\n\t"
	    "vstm.64 %[s], {d0-d7}\n\t"
	    :
	    : [s] "r" (state), [r] "r" (rk)
	    : "memory", "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7"
	   );
}

static void
whirlpool_hash_asmv(uint64_t s[8], const unsigned char buffer[64])
{
	int i;
	uint64_t state[8];
	uint64_t key[8];

	memcpy(key, s, BLOCK_NBYTES);
	memcpy(state, buffer, BLOCK_NBYTES);
	add_round_key(state, key);

	for (i = 0; i < 10; i++) {

		sub_bytes(key);
		sub_bytes(state);

		shift_columns(key);
		shift_columns(state);

		mix_rows(key);
		mix_rows(state);

		key[0] ^= cr_asmv[i];
		add_round_key(state, key);

	}

	asm volatile(
	    "vldm.64 %[s], {d0-d7}\n\t"
	    "vldm.64 %[state], {d8-d15}\n\t"
	    "vldm.64 %[buf], {d16-d23}\n\t"
	    "veor.8 q4, q8\n\t"
	    "veor.8 q5, q9\n\t"
	    "veor.8 q6, q10\n\t"
	    "veor.8 q7, q11\n\t"
	    "veor.8 q0, q4\n\t"
	    "veor.8 q1, q5\n\t"
	    "veor.8 q2, q6\n\t"
	    "veor.8 q3, q7\n\t"
	    "vstm.64 %[s], {d0-d7}\n\t"
	    :
	    : [s] "r" (s), [state] "r" (state), [buf] "r" (buffer)
	    : "memory", "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8",
	      "q9", "q10", "q11"
	    );
}

void
whirlpool_init_asmv(struct context_asmv *ctx)
{
	int i;
	ctx->length[0] = 0;
	ctx->length[1] = 0;

	for (i = 0; i < WHIRLPOOL_NB; i++) {
		((uint64_t *)ctx->buffer)[i] = 0;
		ctx->state[i] = 0;
	}

}

void
whirlpool_update_asmv(struct context_asmv *ctx, const void *msg, uint32_t msglen)
{
	unsigned int n, len;

	n = ctx->length[0] & 0x3F;
	ctx->length[0] += msglen;
	if (n + msglen < 64) {
		/* копируем сообщение в буффер */
		memcpy(ctx->buffer + n, msg, msglen);
	} else {
		/* копируем и хешируем часть сообщения */
		len = 64 - n;
		memcpy(ctx->buffer + n, msg, len);
		whirlpool_hash_asmv(ctx->state, ctx->buffer);
		msglen -= len;
		msg += len;
		/* копируем и хешируем 64-байтовый блок */
		while (msglen >= 64) {
			memcpy(ctx->buffer, msg, 64);
			whirlpool_hash_asmv(ctx->state, ctx->buffer);
			msglen -= len;
			msg += len;
		}
		
		memcpy(ctx->buffer, msg, msglen);
	}
}


static void
uint32_to_bytes(unsigned char *out, const uint32_t *in)
{
	int i, j;

	for (i = j = 0; j < 3; j++) {
		out[i++] = (in[j] >> 24) & 0xff;
		out[i++] = (in[j] >> 16) & 0xff;
		out[i++] = (in[j] >> 8) & 0xff;
		out[i++] = in[j] & 0xff;
	}
}

void
whirlpool_final_asmv(struct context_asmv *ctx, unsigned char digest[64])
{
	static const unsigned char pad[64] = { 0x80, 0x0 };
	unsigned int n, npad;
	uint32_t nbits[3];
	uint8_t nb[32];

	//n = ((ctx->length[0] < 64) ? ctx->length[0]: ctx->length[0] - 64);
	//npad = ((n < 32) ? 32: 96) - n;
	n = ctx->length[0] & 0x3f;
	npad = ((n < 32) ? 32: 96) - n;

	nbits[0] = nbits[1] = 0;
	nbits[1] += ctx->length[0] >> 29;
	nbits[2] = ctx->length[0] << 3;

	memset(nb, 0, sizeof(nb));
	uint32_to_bytes(nb+20, nbits);

	whirlpool_update_asmv(ctx, pad, npad);
	whirlpool_update_asmv(ctx, nb, 32);

	memcpy(digest, ctx->state, 64);
}
