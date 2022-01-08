[Lab] LEA [50]
nc edu-ctf.csie.org 42073

server.py


* 使用方法 remote: python3 solve.py
* 如果是想測試local 的server:把 remote 那邊改成process

* 注意:
* padding 的最後一個byte是跟content長度有關

* 此題重點:

* 目標:想要需要將&& flag 放在原本加密的content的後面
放完之後的hash要我們自己算,並且傳給server,主要就是在解決這個hash怎麼算
* 想解決的問題:因為有salt(admin的password是private的),所以我們無法直接使用我們得到的資訊
去直接得到mac (因為他們再加密的時候有使用到這個salt去加密)
