網址:http://splitline.tw:5000/

1.觀察source:
可以發現我們需要透過post去想辦法access到  http://127.0.0.1:7414/api/v1/looksLikeFlag
但是我們傳入的字串會被過濾掉.符號,我們只能使用URL encode過的字元符號 https://www.w3schools.com/tags/ref_urlencode.ASP
我們就可以get到/looksLikeFlag

2.其中還需要注意的是 looksLikeFlag 下面的code,include 只會回傳true or false,但是它是可以比對subarray的,所以根據類似dp的想法
我們一個字母開始猜，並且往左和往右增長，長到無法再增長就是flag了

