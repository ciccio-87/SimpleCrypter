/*#ifndef _UTILS_H_
#define _UTILS_H_*/

void rand_string(unsigned char *str, int size);
void CompWithRep(unsigned char *tmp, char *check,unsigned char *pass, char *chkstr, int N);

struct hyp_struct {
    char enc_check[9];
    char check[9];
    //int brutelen;
    char pass_hint[9];
};

//#endif