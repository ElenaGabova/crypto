#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <string.h>

#include "../include/aes_asmv.h"
#include "../include/macros.h"

static const uint8_t sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t inv_sbox[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static void
add_round_key_asmv(struct aes_context *ctx, int round)
{
	asm(
	    "vldm.64 %[state], {q0}\n\t"
	    "vldm.64 %[rkey], {q1}\n\t"
	    "veor.8 q0, q1\n\t"
	    "vstm.64 %[state], {q0}\n\t"
	    :
	    : [state] "r" (ctx->state), [rkey] "r" (ctx->w + AES_NB * round)
	    : "memory", "q0", "q1"
	   );
}

static void
sub_bytes_asmv(uint32_t *state, const uint8_t *sbox)
{
	/*
	 * Here we use vtbx ARM instruction to emulate substitute by index. We
	 * need to implement the following:
	 * 	for (i = 0; i < 16; i++)
	 * 		state[i] = sbox[state[i]];
	 * So sbox is main table and state[i] is index variable. Thing is that
	 * state is 16-bytes array, so we can load it in whole to 16-bytes ARM
	 * NEON register, say q0. Next, we need to load main table (sbox that
	 * is). Sbox table is kinda big, it's 256 bytes, and we need some
	 * intermediate registers for calculations, that's why we will use only
	 * half of table. And vldm.64 instruction can't load more than 16
	 * 8-bytes registers, that is the same 128 bytes of table's halves.
	 * Let's store a half of the table in d16-d31 registers. So how can we
	 * index through a loaded half? We will use vtbx instruction. It's used
	 * in the following way:
	 * 	vtbx.8 d_dest, {d_n-d_(n+3)}, d_index.
	 * If we say that a is array of bytes of registers d_n, d_(n+1),
	 * d_(n+2), d_(n+3) then every byte b_i in d_dest is set to
	 * a[d_index[i]] if d_index[i] is in range of 0, …, 31. If d_index[i]
	 * is not in that range then byte b_i is not touched at all. For
	 * example, if
	 * 	a = d_n-d_(n+3) = [11, 55, 65, 44, 45, 23, 32, 56,
	 * 	                   21, 13, 22, 68, 93, 24, 43, 47,
	 * 	                   19, 29, 38, 46, 54, 12, 11, 46,
	 * 	                   93, 74, 77, 12, 48, 34, 32, 90];
	 * 	d_index = [0, 50, 43, 31, 9, 6, 23, 90];
	 * then
	 * 	d_dest[0] = a[d_index[0]] = a[0] = 11;
	 *	d_dest[1] = a[d_index[1]] = a[50] <~ 50 is out of range of
	 *	                                     0, …, 31, so d_dest[1] is
	 *	                                     untouched, it keeps its
	 *	                                     value;
	 *	d_dest[2] = a[d_index[2]] = a[43] <~ 43 is out of range of
	 *	                                     0, …, 31, so d_dest[2] is
	 *	                                     untouched, it keeps its
	 *	                                     value;
	 * 	d_dest[3] = a[d_index[3]] = a[31] = 90;
	 * 	d_dest[4] = a[d_index[4]] = a[9] = 13;
	 * 	d_dest[5] = a[d_index[5]] = a[6] = 32;
	 * 	d_dest[6] = a[d_index[6]] = a[23] = 46;
	 *	d_dest[7] = a[d_index[7]] = a[90] <~ 90 is out of range of
	 *	                                     0, …, 31, so d_dest[7] is
	 *	                                     untouched, it keeps its
	 *	                                     value;
	 * But vtbx can index only through a table of 32 entries and indices
	 * are limited to the mentioned range of 0, …, 31. That's why we use
	 * the following trick. Let's split the whole sbox 256-entries table by
	 * 32-entries sequential pieces. Every index in 0, …, 255 range can be
	 * represended as 32 * i + j where i = 0, …, 7 and j = 0, …, 31. Then
	 * for every i = 0, …, 7 we use i-th piece of sbox table. To properly
	 * index through the piece we prepare indices, subtracting number 32 i
	 * times. And remember, vtbx doesn't touch destination byte if an index
	 * is out of range. The algorithm can be described in the following
	 * way:
	 * 	- load state, load 1st half of sbox table;
	 * 	- using vtbx, set bytes of destination register, indexing
	 * 	  through the entries 0, …, 31;
	 * 	- substract number 32 from indices;
	 * 	- using vtbx, set bytes of destination register, indexing
	 * 	  through the entries 32, …, 63;
	 * 	- substract number 32 from indices;
	 * 	- using vtbx, set bytes of destination register, indexing
	 * 	  through the entries 64, …, 95;
	 * 	- substract number 32 from indices;
	 * 	- using vtbx, set bytes of destination register, indexing
	 * 	  through the entries 96, …, 127;
	 * 	- load 2nd half of sbox table;
	 * 	- substract number 32 from indices;
	 * 	- using vtbx, set bytes of destination register, indexing
	 * 	  through the entries 128, …, 159;
	 * 	- substract number 32 from indices;
	 * 	- using vtbx, set bytes of destination register, indexing
	 * 	  through the entries 160, …, 191;
	 * 	- substract number 32 from indices;
	 * 	- using vtbx, set bytes of destination register, indexing
	 * 	  through the entries 192, …, 223;
	 * 	- substract number 32 from indices;
	 * 	- using vtbx, set bytes of destination register, indexing
	 * 	  through the entries 224, …, 255;
	 * 	- save destination register as new state.
	 */
	asm(
	    "mov r0, %[sbox]\n\t"           /* Save pointer to sbox          */
	    "vldm %[state], {q0}\n\t"       /* Load state to q0              */
	    "vmov.u8 q7, #32\n\t"           /* Set every byte of q7 to 32    */
	    "vldm r0!, {d16-d31}\n\t"       /* Load first half of sbox       */

	    "vtbx.8 d4, {d16-d19}, d0\n\t"  /* Index through entries 0, …, 31*/
	    "vtbx.8 d5, {d16-d19}, d1\n\t"  /* storing result in q2 register */

	    "vsub.i8 q0, q7\n\t"            /* Substract 32 from indices     */
	    "vtbx.8 d4, {d20-d23}, d0\n\t"  /* Index through 32, …, 63       */
	    "vtbx.8 d5, {d20-d23}, d1\n\t"

	    "vsub.i8 q0, q7\n\t"
	    "vtbx.8 d4, {d24-d27}, d0\n\t"  /* Index through 64, …, 95       */
	    "vtbx.8 d5, {d24-d27}, d1\n\t"

	    "vsub.i8 q0, q7\n\t"
	    "vtbx.8 d4, {d28-d31}, d0\n\t"  /* Index through 96, …, 127      */
	    "vtbx.8 d5, {d28-d31}, d1\n\t"

	    "vldm r0, {d16-d31}\n\t"        /* Load 2nd half of sbox         */

	    "vsub.i8 q0, q7\n\t"
	    "vtbx.8 d4, {d16-d19}, d0\n\t"  /* Index through 128, …, 159     */
	    "vtbx.8 d5, {d16-d19}, d1\n\t"

	    "vsub.i8 q0, q7\n\t"
	    "vtbx.8 d4, {d20-d23}, d0\n\t"  /* Index through 160, …, 191     */
	    "vtbx.8 d5, {d20-d23}, d1\n\t"

	    "vsub.i8 q0, q7\n\t"
	    "vtbx.8 d4, {d24-d27}, d0\n\t"  /* Index through 192, …, 223     */
	    "vtbx.8 d5, {d24-d27}, d1\n\t"

	    "vsub.i8 q0, q7\n\t"
	    "vtbx.8 d4, {d28-d31}, d0\n\t"  /* Index through 224, …, 255     */
	    "vtbx.8 d5, {d28-d31}, d1\n\t"

	    "vstm %[state], {q2}\n\t"       /* Store q2 as new state         */
	   :
	   : [state] "r" (state), [sbox] "r" (sbox)
	   : "r0", "q0", "q2", "q7", "q8", "q9", "q10", "q11", "q12", "q13",
	     "q14", "q15"
	   );
}

static const uint8_t sr_indices[] = {
	0, 1, 2, 3,
	5, 6, 7, 4,
	10, 11, 8, 9,
	15, 12, 13, 14,
};

static const uint8_t inv_sr_indices[] = {
	0, 1, 2, 3,
	7, 4, 5, 6,
	10, 11, 8, 9,
	13, 14, 15, 12,
};

static void
shift_rows_asmv(uint32_t* state, const uint8_t *indices)
{
	/* We apply shifts to rows through vtbl command. Indices supplied can
	 * be either sr_indices or inv_sr_indices above.
	 */
	asm(
	    "vldm.64 %[state], {q0}\n\t"
	    "vldm.64 %[indices], {q1}\n\t"
	    "vtbl.8 d4, {d0-d1}, d2\n\t"
	    "vtbl.8 d5, {d0-d1}, d3\n\t"
	    "vstm.64 %[state], {q2}\n\t"
	    :
	    : [state] "r" (state), [indices] "r" (indices)
	    : "memory", "q0", "q1", "q2"
	   );

}

static void
mix_columns_asmv(uint32_t *state)
{
	/*
	 * We need to perform the following operation here. Say, that state is
	 * 16 bytes s0, …, s15, arranged in matrix form:
	 * [ s0  s1  s2  s3  ]
	 * [ s4  s5  s6  s7  ].
	 * [ s8  s9  s10 s11 ]
	 * [ s12 s13 s14 s15 ]
	 * We obtain new state by multiplying it on a MDS-matrix by left in
	 * Rijndael Galois field:
	 * [ 2 3 1 1 ]   [ s0  s1  s2  s3  ]   [ t0  t1  t2  t3  ]
	 * [ 1 2 3 1 ] * [ s4  s5  s6  s7  ] = [ t4  t5  t6  t7  ].
	 * [ 1 1 2 3 ]   [ s8  s9  s10 s11 ]   [ t8  t9  t10 t11 ]
	 * [ 3 1 1 2 ]   [ s12 s13 s14 s15 ]   [ t12 t13 t14 t15 ]
	 * Here bytes t0, …, t15 are new state's bytes. Let's put all rows of
	 * the new state into one giant 16-bytes vector-column, then
	 * [ t0  ]   [ 2 * s0  ]   [ 3 * s4  ]   [ s8  ]   [ s12 ]
	 * [ t1  ]   [ 2 * s1  ]   [ 3 * s5  ]   [ s9  ]   [ s13 ]
	 * [ t2  ]   [ 2 * s2  ]   [ 3 * s6  ]   [ s10 ]   [ s14 ]
	 * [ t3  ]   [ 2 * s3  ]   [ 3 * s7  ]   [ s11 ]   [ s15 ]
	 * [ t4  ]   [ 2 * s4  ]   [ 3 * s8  ]   [ s12 ]   [ s0  ]
	 * [ t5  ]   [ 2 * s5  ]   [ 3 * s9  ]   [ s13 ]   [ s1  ]
	 * [ t6  ]   [ 2 * s6  ]   [ 3 * s10 ]   [ s14 ]   [ s2  ]
	 * [ t7  ] = [ 2 * s7  ] ^ [ 3 * s11 ] ^ [ s15 ] ^ [ s3  ] =
	 * [ t8  ]   [ 2 * s8  ]   [ 3 * s12 ]   [ s0  ]   [ s4  ]
	 * [ t9  ]   [ 2 * s9  ]   [ 3 * s13 ]   [ s1  ]   [ s5  ]
	 * [ t10 ]   [ 2 * s10 ]   [ 3 * s14 ]   [ s2  ]   [ s6  ]
	 * [ t11 ]   [ 2 * s11 ]   [ 3 * s15 ]   [ s3  ]   [ s7  ]
	 * [ t12 ]   [ 2 * s12 ]   [ 3 * s0  ]   [ s4  ]   [ s8  ]
	 * [ t13 ]   [ 2 * s13 ]   [ 3 * s1  ]   [ s5  ]   [ s9  ]
	 * [ t14 ]   [ 2 * s14 ]   [ 3 * s2  ]   [ s6  ]   [ s10 ]
	 * [ t15 ]   [ 2 * s15 ]   [ 3 * s3  ]   [ s7  ]   [ s11 ]
	 *
	 *           [ 2 * s0  ]   [ 2 * s4  ]   [ s4  ]   [ s8  ]   [ s12 ]
	 *           [ 2 * s1  ]   [ 2 * s5  ]   [ s5  ]   [ s9  ]   [ s13 ]
	 *           [ 2 * s2  ]   [ 2 * s6  ]   [ s6  ]   [ s10 ]   [ s14 ]
	 *           [ 2 * s3  ]   [ 2 * s7  ]   [ s7  ]   [ s11 ]   [ s15 ]
	 *           [ 2 * s4  ]   [ 2 * s8  ]   [ s8  ]   [ s12 ]   [ s0  ]
	 *           [ 2 * s5  ]   [ 2 * s9  ]   [ s9  ]   [ s13 ]   [ s1  ]
	 *           [ 2 * s6  ]   [ 2 * s10 ]   [ s10 ]   [ s14 ]   [ s2  ]
	 *         = [ 2 * s7  ] ^ [ 2 * s11 ] ^ [ s11 ] ^ [ s15 ] ^ [ s3  ].
	 *           [ 2 * s8  ]   [ 2 * s12 ]   [ s12 ]   [ s0  ]   [ s4  ]
	 *           [ 2 * s9  ]   [ 2 * s13 ]   [ s13 ]   [ s1  ]   [ s5  ]
	 *           [ 2 * s10 ]   [ 2 * s14 ]   [ s14 ]   [ s2  ]   [ s6  ]
	 *           [ 2 * s11 ]   [ 2 * s15 ]   [ s15 ]   [ s3  ]   [ s7  ]
	 *           [ 2 * s12 ]   [ 2 * s0  ]   [ s0  ]   [ s4  ]   [ s8  ]
	 *           [ 2 * s13 ]   [ 2 * s1  ]   [ s1  ]   [ s5  ]   [ s9  ]
	 *           [ 2 * s14 ]   [ 2 * s2  ]   [ s2  ]   [ s6  ]   [ s10 ]
	 *           [ 2 * s15 ]   [ 2 * s3  ]   [ s3  ]   [ s7  ]   [ s11 ]
	 * We can compute it using 16-bytes NEON registers.
	 */
	asm(
	    "vldm.64 %[state], {q0}\n\t" /* s0, …, s15 are in q0             */

	                                 /* Need to find 2 * s0, …, 2 * s15, */
	                                 /* using one step of polynomial     */
	                                 /* multiplication                   */
	    "vmov.u8 q1, q0\n\t"         /* q1 will store 2 * s0, …, 2 * s15 */
	    "vmov.i8 q2, #0x80\n\t"      /* Set all bytes of q2 to 0x80      */
	    "vmov.i8 q3, #0x1B\n\t"      /* Set all bytes of q3 to 0x1B      */
	                                 /* the Rijndael polynom without     */
	                                 /* highest bit                      */
	    "vtst.8 q2, q1\n\t"          /* Test, if we have higher bits of  */
	                                 /* values set to 1                  */

	    "vand.i8 q2, q3\n\t"         /* Now every byte in q2 is either   */
	                                 /* 0x1B, if higher bit of           */
	                                 /* corresponding value of a was set */
	                                 /* to 1, or 0x00 if it was set to   */

	    "vshl.u8 q1, #1\n\t"        /* Shift all values of by 1 bit to   */
	                                /* left                              */

	    "veor.i8 q1, q2\n\t"        /* XOR values with values of q2      */
	                                /* q1 has 2 * s0, …, 2 * s15 now     */

	    "vext.8 q2, q1, q1, #4\n\t"  /* q2 is 2 * s4, …, 2 * s15, 2 * s0,*/
	                                 /* …, 2 * s3 now                    */
	    "veor.8 q1, q2\n\t"          /* 1st XOR                          */

	    "vext.8 q2, q0, q0, #4\n\t"  /* q2 is s4, …, s15, s0, …, s3 now  */
	    "veor.8 q1, q2\n\t"          /* 2nd XOR                          */

	    "vext.8 q2, q0, q0, #8\n\t"  /* q2 is s8, …, s15, s0, …, s7 now  */
	    "veor.8 q1, q2\n\t"          /* 3d XOR                           */

	    "vext.8 q2, q0, q0, #12\n\t" /* q2 is s12, …, s15, s0, …, s11 now*/
	    "veor.8 q1, q2\n\t"          /* 4th XOR                          */

	    "vstm.64 %[state], {q1}\n\t"
	    :
	    : [state] "r" (state)
	    : "memory", "q0", "q1", "q2", "q3"
	   );
}

static void
inv_mix_columns_asmv(uint32_t *state)
{
	/*
	 * We need to apply inverse transformation to MixColumns. As above,
	 * state is
	 * [ s0  s1  s2  s3  ]
	 * [ s4  s5  s6  s7  ].
	 * [ s8  s9  s10 s11 ]
	 * [ s12 s13 s14 s15 ]
	 * Inverse state is obtained through the following formula:
	 * [ 14 11 13 9  ]   [ s0  s1  s2  s3  ]   [ t0  t1  t2  t3  ]
	 * [ 9  14 11 13 ] * [ s4  s5  s6  s7  ] = [ t4  t5  t6  t7  ].
	 * [ 13 9  14 11 ]   [ s8  s9  s10 s11 ]   [ t8  t9  t10 t11 ]
	 * [ 11 13 9  14 ]   [ s12 s13 s14 s15 ]   [ t12 t13 t14 t15 ]
	 * Here bytes t0, …, t15 are inverse state's bytes. Then
	 * [ t0  ]   [ 14 * s0  ]   [ 11 * s4  ]   [ 13 * s8  ]   [ 9 * s12 ]
	 * [ t1  ]   [ 14 * s1  ]   [ 11 * s5  ]   [ 13 * s9  ]   [ 9 * s13 ]
	 * [ t2  ]   [ 14 * s2  ]   [ 11 * s6  ]   [ 13 * s10 ]   [ 9 * s14 ]
	 * [ t3  ]   [ 14 * s3  ]   [ 11 * s7  ]   [ 13 * s11 ]   [ 9 * s15 ]
	 * [ t4  ]   [ 14 * s4  ]   [ 11 * s8  ]   [ 13 * s12 ]   [ 9 * s0  ]
	 * [ t5  ]   [ 14 * s5  ]   [ 11 * s9  ]   [ 13 * s13 ]   [ 9 * s1  ]
	 * [ t6  ]   [ 14 * s6  ]   [ 11 * s10 ]   [ 13 * s14 ]   [ 9 * s2  ]
	 * [ t7  ] = [ 14 * s7  ] ^ [ 11 * s11 ] ^ [ 13 * s15 ] ^ [ 9 * s3  ] =
	 * [ t8  ]   [ 14 * s8  ]   [ 11 * s12 ]   [ 13 * s0  ]   [ 9 * s4  ]
	 * [ t9  ]   [ 14 * s9  ]   [ 11 * s13 ]   [ 13 * s1  ]   [ 9 * s5  ]
	 * [ t10 ]   [ 14 * s10 ]   [ 11 * s14 ]   [ 13 * s2  ]   [ 9 * s6  ]
	 * [ t11 ]   [ 14 * s11 ]   [ 11 * s15 ]   [ 13 * s3  ]   [ 9 * s7  ]
	 * [ t12 ]   [ 14 * s12 ]   [ 11 * s0  ]   [ 13 * s4  ]   [ 9 * s8  ]
	 * [ t13 ]   [ 14 * s13 ]   [ 11 * s1  ]   [ 13 * s5  ]   [ 9 * s9  ]
	 * [ t14 ]   [ 14 * s14 ]   [ 11 * s2  ]   [ 13 * s6  ]   [ 9 * s10 ]
	 * [ t15 ]   [ 14 * s15 ]   [ 11 * s3  ]   [ 13 * s7  ]   [ 9 * s11 ]
	 * We can obtain these columns in the following way:
	 * [ 9 * s12 ]   [ 8 * s12 ]   [ s12 ]
	 * [ 9 * s13 ]   [ 8 * s13 ]   [ s13 ]
	 * [ 9 * s14 ]   [ 8 * s14 ]   [ s14 ]
	 * [ 9 * s15 ]   [ 8 * s15 ]   [ s15 ]
	 * [ 9 * s0  ]   [ 8 * s0  ]   [ s0  ]
	 * [ 9 * s1  ]   [ 8 * s1  ]   [ s1  ]
	 * [ 9 * s2  ]   [ 8 * s2  ]   [ s2  ]
	 * [ 9 * s3  ] = [ 8 * s3  ] ^ [ s3  ];
	 * [ 9 * s4  ]   [ 8 * s4  ]   [ s4  ]
	 * [ 9 * s5  ]   [ 8 * s5  ]   [ s5  ]
	 * [ 9 * s6  ]   [ 8 * s6  ]   [ s6  ]
	 * [ 9 * s7  ]   [ 8 * s7  ]   [ s7  ]
	 * [ 9 * s8  ]   [ 8 * s8  ]   [ s8  ]
	 * [ 9 * s9  ]   [ 8 * s9  ]   [ s9  ]
	 * [ 9 * s10 ]   [ 8 * s10 ]   [ s10 ]
	 * [ 9 * s11 ]   [ 8 * s11 ]   [ s11 ]
	 *
	 * [ 11 * s4  ]   [ 9 * s4  ]   [ 2 * s4  ]
	 * [ 11 * s5  ]   [ 9 * s5  ]   [ 2 * s5  ]
	 * [ 11 * s6  ]   [ 9 * s6  ]   [ 2 * s6  ]
	 * [ 11 * s7  ]   [ 9 * s7  ]   [ 2 * s7  ]
	 * [ 11 * s8  ]   [ 9 * s8  ]   [ 2 * s8  ]
	 * [ 11 * s9  ]   [ 9 * s9  ]   [ 2 * s9  ]
	 * [ 11 * s10 ]   [ 9 * s10 ]   [ 2 * s10 ]
	 * [ 11 * s11 ] = [ 9 * s11 ] ^ [ 2 * s11 ];
	 * [ 11 * s12 ]   [ 9 * s12 ]   [ 2 * s12 ]
	 * [ 11 * s13 ]   [ 9 * s13 ]   [ 2 * s13 ]
	 * [ 11 * s14 ]   [ 9 * s14 ]   [ 2 * s14 ]
	 * [ 11 * s15 ]   [ 9 * s15 ]   [ 2 * s15 ]
	 * [ 11 * s0  ]   [ 9 * s0  ]   [ 2 * s0  ]
	 * [ 11 * s1  ]   [ 9 * s1  ]   [ 2 * s1  ]
	 * [ 11 * s2  ]   [ 9 * s2  ]   [ 2 * s2  ]
	 * [ 11 * s3  ]   [ 9 * s3  ]   [ 2 * s3  ]
	 *
	 * [ 13 * s8  ]   [ 9 * s8  ]   [ 4 * s8  ]
	 * [ 13 * s9  ]   [ 9 * s9  ]   [ 4 * s9  ]
	 * [ 13 * s10 ]   [ 9 * s10 ]   [ 4 * s10 ]
	 * [ 13 * s11 ]   [ 9 * s11 ]   [ 4 * s11 ]
	 * [ 13 * s12 ]   [ 9 * s12 ]   [ 4 * s12 ]
	 * [ 13 * s13 ]   [ 9 * s13 ]   [ 4 * s13 ]
	 * [ 13 * s14 ]   [ 9 * s14 ]   [ 4 * s14 ]
	 * [ 13 * s15 ] = [ 9 * s15 ] ^ [ 4 * s15 ];
	 * [ 13 * s0  ]   [ 9 * s0  ]   [ 4 * s0  ]
	 * [ 13 * s1  ]   [ 9 * s1  ]   [ 4 * s1  ]
	 * [ 13 * s2  ]   [ 9 * s2  ]   [ 4 * s2  ]
	 * [ 13 * s3  ]   [ 9 * s3  ]   [ 4 * s3  ]
	 * [ 13 * s4  ]   [ 9 * s4  ]   [ 4 * s4  ]
	 * [ 13 * s5  ]   [ 9 * s5  ]   [ 4 * s5  ]
	 * [ 13 * s6  ]   [ 9 * s6  ]   [ 4 * s6  ]
	 * [ 13 * s7  ]   [ 9 * s7  ]   [ 4 * s7  ]
	 *
	 * [ 14 * s0  ]   [ 8 * s0  ]   [ 4 * s0  ]   [ 2 * s0  ]
	 * [ 14 * s1  ]   [ 8 * s1  ]   [ 4 * s1  ]   [ 2 * s1  ]
	 * [ 14 * s2  ]   [ 8 * s2  ]   [ 4 * s2  ]   [ 2 * s2  ]
	 * [ 14 * s3  ]   [ 8 * s3  ]   [ 4 * s3  ]   [ 2 * s3  ]
	 * [ 14 * s4  ]   [ 8 * s4  ]   [ 4 * s4  ]   [ 2 * s4  ]
	 * [ 14 * s5  ]   [ 8 * s5  ]   [ 4 * s5  ]   [ 2 * s5  ]
	 * [ 14 * s6  ]   [ 8 * s6  ]   [ 4 * s6  ]   [ 2 * s6  ]
	 * [ 14 * s7  ] = [ 8 * s7  ] ^ [ 4 * s7  ] ^ [ 2 * s7  ].
	 * [ 14 * s8  ]   [ 8 * s8  ]   [ 4 * s8  ]   [ 2 * s8  ]
	 * [ 14 * s9  ]   [ 8 * s9  ]   [ 4 * s9  ]   [ 2 * s9  ]
	 * [ 14 * s10 ]   [ 8 * s10 ]   [ 4 * s10 ]   [ 2 * s10 ]
	 * [ 14 * s11 ]   [ 8 * s11 ]   [ 4 * s11 ]   [ 2 * s11 ]
	 * [ 14 * s12 ]   [ 8 * s12 ]   [ 4 * s12 ]   [ 2 * s12 ]
	 * [ 14 * s13 ]   [ 8 * s13 ]   [ 4 * s13 ]   [ 2 * s13 ]
	 * [ 14 * s14 ]   [ 8 * s14 ]   [ 4 * s14 ]   [ 2 * s14 ]
	 * [ 14 * s15 ]   [ 8 * s15 ]   [ 4 * s15 ]   [ 2 * s15 ]
	 */
	asm(
	    "vldm.64 %[state], {q0}\n\t" /* s0, …, s15 are in q0             */

	                                 /* Need to find 2 * s0, …, 2 * s15, */
	                                 /* using one step of polynomial     */
	                                 /* multiplication                   */
	    "vmov.u8 q1, q0\n\t"         /* q1 will store 2 * s0, …, 2 * s15 */
	    "vmov.i8 q4, #0x80\n\t"      /* Set all bytes of q4 to 0x80      */
	    "vmov.i8 q5, #0x1B\n\t"      /* Set all bytes of q5 to 0x1B      */
	                                 /* the Rijndael polynom without     */
	                                 /* highest bit                      */
	    "vtst.8 q6, q1, q4\n\t"      /* Test, if we have higher bits of  */
	                                 /* values set to 1                  */

	    "vand.i8 q6, q5\n\t"         /* Now every byte in q6 is either   */
	                                 /* 0x1B, if higher bit of           */
	                                 /* corresponding value of a was set */
	                                 /* to 1, or 0x00 if it was set to   */

	    "vshl.u8 q1, #1\n\t"        /* Shift all values of by 1 bit to   */
	                                /* left                              */

	    "veor.i8 q1, q6\n\t"        /* XOR values with values of q6      */
	                                /* q1 has 2 * s0, …, 2 * s15 now     */

	    "vmov.u8 q2, q1\n\t"         /* q2 will store 4 * s0, …, 4 * s15 */
	    "vtst.8 q6, q2, q4\n\t"
	    "vand.i8 q6, q5\n\t"
	    "vshl.u8 q2, #1\n\t"
	    "veor.i8 q2, q6\n\t"

	    "vmov.u8 q3, q2\n\t"         /* q3 will store 8 * s0, …, 8 * s15 */
	    "vtst.8 q6, q3, q4\n\t"
	    "vand.i8 q6, q5\n\t"
	    "vshl.u8 q3, #1\n\t"
	    "veor.i8 q3, q6\n\t"

	                                 /* q4 will store 9 * s12, 9 * s13,  */
	                                 /* 9 * s14, 9 * s15, 9 * s0, …,     */
	                                 /* 9 * s11                          */

	    "vext.8 q4, q3, q3, #12\n\t" /* q4 is 8 * s12, …, 8 * s15,       */
	                                 /* 8 * s0, …, 8 * s11 now           */

	    "vext.8 q5, q0, q0, #12\n\t" /* q5 is s12, …, s15, s0, …, s11 now*/
	    "veor.8 q4, q5\n\t"

	    "vmov.8 q7, q4\n\t"          /* q7 to store result               */

	                                 /* Let's find 11 * s4, …, 11 * s15, */
	                                 /* 11 * s0, …, 11 * s3              */

	    "vext.8 q4, q4, #8\n\t"      /* q4 is 9 * s4, …, 9 * s15,        */
	                                 /* 9 * s0, …, 9 * s3 now            */
	    "veor.8 q7, q4\n\t"

	    "vext.8 q5, q1, q1, #4\n\t"  /* q5 is 2 * s4, …, 2 * s15, 2 * s0,*/
	                                 /* …, 2 * s3 now                    */
	    "veor.8 q7, q5\n\t"

	                                 /* Let's find 13 * s8, …, 13 * s15, */
	                                 /* 13 * s0, …, 13 * s7              */

	    "vext.8 q4, q4, #4\n\t"      /* q4 is 9 * s8, …, 9 * s15,        */
	                                 /* 9 * s0, …, 9 * s7 now            */
	    "veor.8 q7, q4\n\t"

	    "vext.8 q5, q2, q2, #8\n\t"  /* q5 is 4 * s8, …, 4 * s15, 4 * s0,*/
	                                 /* …, 4 * s8 now                    */
	    "veor.8 q7, q5\n\t"

	                                 /* Finally, 14 * s0, …, 14 * s15    */
	    "veor.8 q7, q3\n\t"
	    "veor.8 q7, q2\n\t"
	    "veor.8 q7, q1\n\t"

	    "vstm.64 %[state], {q7}\n\t"
	    :
	    : [state] "r" (state)
	    : "memory", "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7"
	   );
}

void
aes_encrypt_asmv(struct aes_context *ctx, const uint8_t *input, uint8_t *output)
{
	uint8_t *sp;
	sp = (uint8_t *) ctx->state;

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++)
			sp[i * 4 + j] = input[j * 4 + i];
	}

 	add_round_key_asmv(ctx, 0);
	for (int i = 1; i < ctx->nr; i++) {
		sub_bytes_asmv(ctx->state, sbox);
		shift_rows_asmv(ctx->state, sr_indices);
		mix_columns_asmv(ctx->state);
		add_round_key_asmv(ctx, i);
	}
	sub_bytes_asmv(ctx->state, sbox);
	shift_rows_asmv(ctx->state, sr_indices);
	add_round_key_asmv(ctx, ctx->nr);

	for (int i = 0; i < AES_NB; i++) {
			for (int j = 0; j < AES_NB; j++)
				output[i * AES_NB + j] = sp[j * AES_NB + i];
		}
}

void
aes_decrypt_asmv(struct aes_context *ctx, const uint8_t *input, uint8_t *output)
{
	uint8_t *sp;

	sp = (uint8_t *) ctx->state;

	for (int i = 0; i < AES_NB; i++) {
		for (int j = 0; j < AES_NB; j++)
			sp[i * AES_NB + j] = input[j * AES_NB + i];
	}

	add_round_key_asmv(ctx,  ctx->nr);
	for (int i = ctx->nr - 1; i > 0; i-- ) {
		shift_rows_asmv(ctx->state, inv_sr_indices);
		sub_bytes_asmv(ctx->state, inv_sbox);
		add_round_key_asmv(ctx, i);
		inv_mix_columns_asmv(ctx->state);
	}
	shift_rows_asmv(ctx->state, inv_sr_indices);
	sub_bytes_asmv(ctx->state, inv_sbox);
	add_round_key_asmv(ctx, 0);

	for (int i = 0; i < AES_NB; i++) {
			for (int j = 0; j < AES_NB; j++)
				output[i * AES_NB + j] = sp[j * AES_NB + i];
		}
}
