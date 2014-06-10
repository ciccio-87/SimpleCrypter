#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "c_des.h"

void CompWithRep(unsigned char *tmp, char *check,unsigned char *pass, char *chkstr, int N) {
  char line[N];
  //unsigned char tmp[8];
  char cltmp[9];
  //key_set *key = (key_set *)malloc(17*sizeof(key_set));;
  int c = 0;
  char d;
  int i,cc,j;
  //int start = 23;
  //int end = 123;
  char start = 33;
  char end = 122;
  char endstr[N+1];
  
  for (i = 0; i < N; i ++){
      endstr[i] = end;
  }
  endstr[i] = '\0';
  //printf("endstr = %s\n",endstr);
  //d = getchar();
  for (i = 0; i < N; i++) {
      line[i] = 43;
  }
  do {
      for (i = 0; i < 8-N; i++) {
	  tmp[i] = pass[i];
      }
      //strncpy(tmp,pass,8-N);
      /*if (!(c%50)) {
	  printf("%s\n",cltmp);
	  printf("%s\n",tmp);
	  d = getchar();
      }*/
      c ++;
      //printf("%s\n",line);
      for (i = N-1; i >= 0; i--) {
	  if (line[i] < end) {
	      line[i] ++;
	      break;
	  }
      }
      cc = i;
      if (i < N) {
          for (j = i+1; j < N; j++) {
	      line[j] = start;
	  }
      }
      for (j = 0; j < N; j++) {
	  tmp[j+8-N] = line[j];
      }
      //printf("%s\n",tmp);
      //key = (key_set *)malloc(17*sizeof(key_set));
      //memset(key,0,17*sizeof(key_set));
      memset(cltmp,0,9*sizeof(char));
      //memset(tmp,0,8*sizeof(char));
      
      DesDecrypt(check, tmp, cltmp);
      //free(key);
      cltmp[8] = '\0';
      if (!(strcmp(cltmp,chkstr))) { //|| !(strcmp(tmp,"prova123"))){
	  /*printf("found!!\n");
	  printf("%s\n",tmp);
	  printf("%s\n%s\n",cltmp,chkstr);*/
	  //printf("%s\n", check);
	  //print_key_set(key);
	  //cltmp[8] = '\0';
	  break;
      }
  } while(strcmp(line,endstr));
  //printf("%i\n",strlen(tmp));
}

void rand_string(unsigned char *str, int size) {
    //char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMOPQRSTUVWXYZ";
    char charset[] = "!\"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz";
    if (size) {
        //--size;
	int n;
	time_t t;
	srand((unsigned) time(&t));
        for (n = 0; n < size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        //str[size] = '\0';
    }
}

struct hyp_struct {
    char enc_check[9];
    char check[9];
    //int brutelen;
    char pass_hint[9];
};

/*int hyp_file(char *infile, char *key, char *outfile, int brutelen, char *check, char *enc_check, char *pass_hint) {
	FILE *out_file = fopen(outfile, "wb");
	if (!out_file) {
		printf("Could not open output file to read data.");
		return 1;
	}
	struct hyp_struct my_hyp;
	//my_hyp.brutelen = brutelen;  //TODO: FIX THIS SHIT
	strcpy(my_hyp.enc_check, enc_check);
	my_hyp.enc_check[8] = '\0';
	strcpy(my_hyp.check, check);
	strcpy(my_hyp.pass_hint, pass_hint);
	fwrite(&my_hyp, sizeof(struct hyp_struct), 1 ,out_file);
	fclose(out_file);
	encrypt_file(infile, key, outfile,1);
	return 0;
}*/

/*int main(int argc, char **argv) {
    //puts(")~��Hb�");
    //puts(")~\xa0\xfdHb\xa2\x11");
    char pass[8];
    //CompWithRep(pass,")~\xa0\xfdHb\xa2\x11","prova","blablala",3);
    //DesDecrypt(")~\xa0\xfdHb\xa2\x11","prova123",pass);
    //printf("Pass = %s\n",pass);
    //decrypt_file("enc", pass, "dec", 0);
    encrypt_file("loadEXE.cpp","prova123","enc",0);
    unsigned char *buf;
    decrypt_to_buf("enc","prova123",&buf,0);
    printf("%s",buf);
}*/