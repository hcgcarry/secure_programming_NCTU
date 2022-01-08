http://splitline.tw:8100


* 觀察:點進其他的Ranibow Cat 可以看到url :
http://splitline.tw:8100/item/5429
我們猜flag的是
http://splitline.tw:8100/item/5430
猜中


2. 錢不購買:用f12 去查看Buy 那邊的source code, 可以看到前端會回傳cost 到後端,估計是拿這個值在後端做減法,直接value改小就好
