http://dvd.chal.h4ck3r.quest:10001/login

技能點：Path traversal、SQL injection、Signed Cookie


Hints:
* Source code 中 <CENSORED> 的相關部分是刻意被移掉的內容，伺服器上會有不同的配置

* RTFM (Important!) https://pkg.go.dev/net/http (Path traverasl)

* 你需要試著找到伺服器上的 SECRET_KEY (Path traverasl)

* 如果你看到任何不是 FLAG{...} 格式的東西，那它就不會是 flag




## solve
* path traversal in golang, solved the url clean problem:
https://ilyaglotov.com/blog/servemux-and-path-traversal?fbclid=IwAR.0wdUxqTP3r9Y18m5bapmkEdtRHxCpWoQgJNCk2pxs5Q0GmhRd_wUyYfhs


* 
secret_key:d2908c1de1cd896d90f09df7df67e1d4