#include<stdio.h>

int main(int argc, char* argv[]){
    if (argc < 2) return 1;
    int num,r,reverse=0;

//    printf("Enter any number: ");
//    scanf("%d",&num);
    num = argv[1][0];

    while(num){
         r=num%10;
         reverse=reverse*10+r;
         num=num/10;
    }

    printf("Reversed of number: %d\n",reverse);
    return 0;
}
