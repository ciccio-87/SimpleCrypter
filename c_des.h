#ifndef _UTILS_H_
#define _UTILS_H_

void DES(unsigned char *m, unsigned char *k, int encrypt, unsigned char*out);
void DesEncrypt(unsigned char *m, unsigned char *k, unsigned char*out);
void DesDecrypt(unsigned char *m, unsigned char *k, unsigned char*out);

void TripleDesEncryptCBC(unsigned char *m, int msg_len, unsigned char *k, unsigned char *out);
void TripleDesDecryptCBC(unsigned char *m, int msg_len, unsigned char *k, unsigned char *out);

int encrypt_file(char *infile, unsigned char *des_key, unsigned char *outfile);
int decrypt_file(char *infile, char *des_key, char *outfile);

int decrypt_to_buf(char *infile, unsigned char *des_key, unsigned char **outbuf);


#endif