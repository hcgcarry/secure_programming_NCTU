P.S. 每天 00:00 會將 tmp 目錄下的 fifo 清掉

nc edu-ctf.zoolab.org 30207



# steps
* python3 chat_server.py
* python3 solve.py
* solve.py會要求輸入chat_server的token,手動copy 過去

* key 在malloc的時候會被清調
* 改chunck size 再把它free調,如果是進tcache的話可以如期進入改完
size的tcache,如果進入smallbin , unsorted bin ,的話會報錯

* rellocate 的如果top chunck就在下面,會直接擴展


FLAG{beeeeeeOwO}

