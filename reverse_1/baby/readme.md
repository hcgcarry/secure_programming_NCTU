
* step:
1. gdb baby
3. 可以發現他把source的東西跟另一個array做xor,然後用
sys_write寫出去,所以我們想要看這個寫出去的value is what,
we set the break point at 4010AE, and continue to see what it write to si
2. b *0x4010AE
3. r
4. c ,c,c,c ...


FLAG{This_is_your_flag_abcd}

