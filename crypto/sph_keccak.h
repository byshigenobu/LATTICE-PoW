/* $Id: sph_keccak.h 216 2010-06-08 09:46:57Z tp $ */
2/**
3 * Keccak interface. This is the interface for Keccak with the
4 * recommended parameters for SHA-3, with output lengths 224, 256,
5 * 384 and 512 bits.
6 *
7 * ==========================(LICENSE BEGIN)============================
8 *
9 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
10 * 
11 * Permission is hereby granted, free of charge, to any person obtaining
12 * a copy of this software and associated documentation files (the
13 * "Software"), to deal in the Software without restriction, including
14 * without limitation the rights to use, copy, modify, merge, publish,
15 * distribute, sublicense, and/or sell copies of the Software, and to
16 * permit persons to whom the Software is furnished to do so, subject to
17 * the following conditions:
18 * 
19 * The above copyright notice and this permission notice shall be
20 * included in all copies or substantial portions of the Software.
21 * 
22 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
23 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
24 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
25 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
26 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
27 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
28 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
29 *
30 * ===========================(LICENSE END)=============================
31 *
32 * @file     sph_keccak.h
33 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
34 */
35
36#ifndef SPH_KECCAK_H__
37#define SPH_KECCAK_H__
38
39#ifdef __cplusplus
40extern "C"{
41#endif
42
43#include <stddef.h>
44#include "sph_types.h"
45
46/**
47 * Output size (in bits) for Keccak-224.
48 */
49#define SPH_SIZE_keccak224   224
50
51/**
52 * Output size (in bits) for Keccak-256.
53 */
54#define SPH_SIZE_keccak256   256
55
56/**
57 * Output size (in bits) for Keccak-384.
58 */
59#define SPH_SIZE_keccak384   384
60
61/**
62 * Output size (in bits) for Keccak-512.
63 */
64#define SPH_SIZE_keccak512   512
65
66/**
67 * This structure is a context for Keccak computations: it contains the
68 * intermediate values and some data from the last entered block. Once a
69 * Keccak computation has been performed, the context can be reused for
70 * another computation.
71 *
72 * The contents of this structure are private. A running Keccak computation
73 * can be cloned by copying the context (e.g. with a simple
74 * <code>memcpy()</code>).
75 */
76typedef struct {
77#ifndef DOXYGEN_IGNORE
78	unsigned char buf[144];    /* first field, for alignment */
79	size_t ptr, lim;
80	union {
81#if SPH_64
82		sph_u64 wide[25];
83#endif
84		sph_u32 narrow[50];
85	} u;
86#endif
87} sph_keccak_context;
88
89/**
90 * Type for a Keccak-224 context (identical to the common context).
91 */
92typedef sph_keccak_context sph_keccak224_context;
93
94/**
95 * Type for a Keccak-256 context (identical to the common context).
96 */
97typedef sph_keccak_context sph_keccak256_context;
98
99/**
100 * Type for a Keccak-384 context (identical to the common context).
101 */
102typedef sph_keccak_context sph_keccak384_context;
103
104/**
105 * Type for a Keccak-512 context (identical to the common context).
106 */
107typedef sph_keccak_context sph_keccak512_context;
108
109/**
110 * Initialize a Keccak-224 context. This process performs no memory allocation.
111 *
112 * @param cc   the Keccak-224 context (pointer to a
113 *             <code>sph_keccak224_context</code>)
114 */
115void sph_keccak224_init(void *cc);
116
117/**
118 * Process some data bytes. It is acceptable that <code>len</code> is zero
119 * (in which case this function does nothing).
120 *
121 * @param cc     the Keccak-224 context
122 * @param data   the input data
123 * @param len    the input data length (in bytes)
124 */
125void sph_keccak224(void *cc, const void *data, size_t len);
126
127/**
128 * Terminate the current Keccak-224 computation and output the result into
129 * the provided buffer. The destination buffer must be wide enough to
130 * accomodate the result (28 bytes). The context is automatically
131 * reinitialized.
132 *
133 * @param cc    the Keccak-224 context
134 * @param dst   the destination buffer
135 */
136void sph_keccak224_close(void *cc, void *dst);
137
138/**
139 * Add a few additional bits (0 to 7) to the current computation, then
140 * terminate it and output the result in the provided buffer, which must
141 * be wide enough to accomodate the result (28 bytes). If bit number i
142 * in <code>ub</code> has value 2^i, then the extra bits are those
143 * numbered 7 downto 8-n (this is the big-endian convention at the byte
144 * level). The context is automatically reinitialized.
145 *
146 * @param cc    the Keccak-224 context
147 * @param ub    the extra bits
148 * @param n     the number of extra bits (0 to 7)
149 * @param dst   the destination buffer
150 */
151void sph_keccak224_addbits_and_close(
152	void *cc, unsigned ub, unsigned n, void *dst);
153
154/**
155 * Initialize a Keccak-256 context. This process performs no memory allocation.
156 *
157 * @param cc   the Keccak-256 context (pointer to a
158 *             <code>sph_keccak256_context</code>)
159 */
160void sph_keccak256_init(void *cc);
161
162/**
163 * Process some data bytes. It is acceptable that <code>len</code> is zero
164 * (in which case this function does nothing).
165 *
166 * @param cc     the Keccak-256 context
167 * @param data   the input data
168 * @param len    the input data length (in bytes)
169 */
170void sph_keccak256(void *cc, const void *data, size_t len);
171
172/**
173 * Terminate the current Keccak-256 computation and output the result into
174 * the provided buffer. The destination buffer must be wide enough to
175 * accomodate the result (32 bytes). The context is automatically
176 * reinitialized.
177 *
178 * @param cc    the Keccak-256 context
179 * @param dst   the destination buffer
180 */
181void sph_keccak256_close(void *cc, void *dst);
182
183/**
184 * Add a few additional bits (0 to 7) to the current computation, then
185 * terminate it and output the result in the provided buffer, which must
186 * be wide enough to accomodate the result (32 bytes). If bit number i
187 * in <code>ub</code> has value 2^i, then the extra bits are those
188 * numbered 7 downto 8-n (this is the big-endian convention at the byte
189 * level). The context is automatically reinitialized.
190 *
191 * @param cc    the Keccak-256 context
192 * @param ub    the extra bits
193 * @param n     the number of extra bits (0 to 7)
194 * @param dst   the destination buffer
195 */
196void sph_keccak256_addbits_and_close(
197	void *cc, unsigned ub, unsigned n, void *dst);
198
199/**
200 * Initialize a Keccak-384 context. This process performs no memory allocation.
201 *
202 * @param cc   the Keccak-384 context (pointer to a
203 *             <code>sph_keccak384_context</code>)
204 */
205void sph_keccak384_init(void *cc);
206
207/**
208 * Process some data bytes. It is acceptable that <code>len</code> is zero
209 * (in which case this function does nothing).
210 *
211 * @param cc     the Keccak-384 context
212 * @param data   the input data
213 * @param len    the input data length (in bytes)
214 */
215void sph_keccak384(void *cc, const void *data, size_t len);
216
217/**
218 * Terminate the current Keccak-384 computation and output the result into
219 * the provided buffer. The destination buffer must be wide enough to
220 * accomodate the result (48 bytes). The context is automatically
221 * reinitialized.
222 *
223 * @param cc    the Keccak-384 context
224 * @param dst   the destination buffer
225 */
226void sph_keccak384_close(void *cc, void *dst);
227
228/**
229 * Add a few additional bits (0 to 7) to the current computation, then
230 * terminate it and output the result in the provided buffer, which must
231 * be wide enough to accomodate the result (48 bytes). If bit number i
232 * in <code>ub</code> has value 2^i, then the extra bits are those
233 * numbered 7 downto 8-n (this is the big-endian convention at the byte
234 * level). The context is automatically reinitialized.
235 *
236 * @param cc    the Keccak-384 context
237 * @param ub    the extra bits
238 * @param n     the number of extra bits (0 to 7)
239 * @param dst   the destination buffer
240 */
241void sph_keccak384_addbits_and_close(
242	void *cc, unsigned ub, unsigned n, void *dst);
243
244/**
245 * Initialize a Keccak-512 context. This process performs no memory allocation.
246 *
247 * @param cc   the Keccak-512 context (pointer to a
248 *             <code>sph_keccak512_context</code>)
249 */
250void sph_keccak512_init(void *cc);
251
252/**
253 * Process some data bytes. It is acceptable that <code>len</code> is zero
254 * (in which case this function does nothing).
255 *
256 * @param cc     the Keccak-512 context
257 * @param data   the input data
258 * @param len    the input data length (in bytes)
259 */
260void sph_keccak512(void *cc, const void *data, size_t len);
261
262/**
263 * Terminate the current Keccak-512 computation and output the result into
264 * the provided buffer. The destination buffer must be wide enough to
265 * accomodate the result (64 bytes). The context is automatically
266 * reinitialized.
267 *
268 * @param cc    the Keccak-512 context
269 * @param dst   the destination buffer
270 */
271void sph_keccak512_close(void *cc, void *dst);
272
273/**
274 * Add a few additional bits (0 to 7) to the current computation, then
275 * terminate it and output the result in the provided buffer, which must
276 * be wide enough to accomodate the result (64 bytes). If bit number i
277 * in <code>ub</code> has value 2^i, then the extra bits are those
278 * numbered 7 downto 8-n (this is the big-endian convention at the byte
279 * level). The context is automatically reinitialized.
280 *
281 * @param cc    the Keccak-512 context
282 * @param ub    the extra bits
283 * @param n     the number of extra bits (0 to 7)
284 * @param dst   the destination buffer
285 */
286void sph_keccak512_addbits_and_close(
287	void *cc, unsigned ub, unsigned n, void *dst);
288
289#ifdef __cplusplus
290}
291#endif
292
293#endif
294
