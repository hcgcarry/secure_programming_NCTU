#include<iostream>
#include<vector>
#include<iostream>
using namespace std;

int main(void){

  long unsigned int tmp[10]= {0x9dc2a589b5b3beb4, 0xa7c2abada5b3a5ad,0xb99184beadc2c7ad, 0xad9a91869385ad8b, 0xcbc6a4b0beadad84, 0x008f95b7b0a2a6};
  char* chr = (char*)&tmp;
  // cout << "answer:";
  char hash = 0xf2;
  for(int i=0;i<0x3e;i++){
    char a=  *(chr+i);
    printf("%c", hash ^ a);
  }


    

}