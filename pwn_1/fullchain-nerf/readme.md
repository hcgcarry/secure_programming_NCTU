nc edu-ctf.zoolab.org 30206

# 這題好像要多跑幾次,因為有可能沒有出來

ROPgadget --binary ./test --only "pop|ret"



fullchain-nerf 大致流程: 
1. 用 printf format string 得到 stack address 跟 base address    
2. 用 puts plt 跟 puts got 得到 libc address     
3.  stack 上選一塊地方做為新的 stack，用 libc 中 I/O function 讀入任意長 ROP chain 到新的 stack 在的地方    
4.  stack pivoting 到新的 stack 執行之前讀入的 ROP chain