#include <stdint.h> // for uint8_t
#include <stdio.h> // for printf
#include<inttypes.h>

uint32_t add_ntoh(uint32_t n1, uint32_t n2){
    return n1 & n2;
}

uint32_t my_ntoh(uint32_t n){
	int n1,n2,n3,n4;
	n1 = (n >> 24) & 0xff;
	n2 = (n >> 8) & 0xff00;
	n3 = (n << 8) & 0xff0000;
	n4 = (n << 24) & 0xff000000;

	return (n1 | n2 | n3 | n4);
}


int main(int argc, char* argv[]){
    
    uint32_t n1,n2;
    FILE *fp1,*fp2;

    fp1 = fopen(argv[1], "rb");
    fp2 = fopen(argv[2], "rb");

    fread(&n1,4,1,fp1);
    fread(&n2,4,1,fp2);

    n1 = my_ntoh(n1);
    n2 = my_ntoh(n2);

    printf("n1 is : %"PRIx32"\n",n1);
    printf("n2 is : %"PRIx32"\n",n2);

    printf("%"PRIu32"(0x%"PRIx32") +%"PRIu32"(0x%"PRIx32") = %"PRIu32"(0x%"PRIx32")\n",n1,n1,n2,n2,(n1+n2),(n1+n2));

}