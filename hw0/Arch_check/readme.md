1. checksec: 可以發現  arch_check 沒有 Stack Canaries 也沒開PIE


2. 使用ghidra:
我們在裡面發現了一個debug的function, 他呼叫了shell
3. disasm: objdump -D arch_check:
main :read 沒有限制字數並且是讀到一個32byte的buffer


4. 結合上面資訊，我們可以透過buffer overflow 的技巧，將main的return address 覆蓋掉變成我們想要的function的address
計算return address 位置:buffer 32byte,加上RBP 8 byte, 就是我們想要的位置，
把target的位置寫進去(因為沒開PIE所以直接把objdump看到的位置寫進去)，就完成了
