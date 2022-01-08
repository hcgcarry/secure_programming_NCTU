* 解題重點:
1.使用ghidra :main可以發現game_logic 帶入的參數是 local_38的地址,而bingo後面只是把這個地址上面的東西^0xf2並且Print出來

2.local這個變數似乎只會站她擁有的內容的大小ex: 0xf2 只佔一個byte ,0xfff3 占兩個byte

3.寫一個程式,把ghidra看到的local那一堆數字做 ^0xf2的操作並且printf出來就好(注意不要用cout他似乎會把char轉成 ostream_basic<char> )