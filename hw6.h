/*
 * hw6.h
 *
 *  Created on: Apr 11, 2015
 *      Author: prabhaks
 */

#ifndef HW5_H_
#define HW5_H_

#define MAXPATHLENGTH 256
#define KEYLEN 32
#define POLYLEN 16
#define DIR_SEP '/'

extern void ProcessTableCheck(FILE*);
extern void ProcessModProd(char*, char*);
extern void ProcessKeyExpand(char*, FILE*);
extern void ProcessEncrypt(char*, FILE*, FILE*);
extern void ProcessDecrypt(char*, FILE*, FILE*);
extern void ProcessInverse(char*);

#endif /* HW5_H_ */
