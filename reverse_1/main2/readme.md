* flag location:
RunFunc1

* solution 1:
runfunc1 裡面的arg1 就是argc, arg2 就是argv
把argv的type改成 char** 就很好懂了



*  solution 2:build break point to 

跟改 reg or mem 去改變 if 流程
2       breakpoint     keep y   0x000055555555524c <RunFunc1+163>


跟改 reg or mem 去改變 if 流程
4       breakpoint     keep y   0x00005555555551b5 <RunFunc1+12>
觀看寫入的flag
6       breakpoint     keep y   0x0000555555555283 <RunFunc1+218>



FLAG{Faker_BibleThump}