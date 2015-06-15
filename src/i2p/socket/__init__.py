#
# i2p.socket
#

__doc__ = """
::::::::cccclooddxxxxxxxxkkkkkkkkkkkkkkkkkkkkxod0NX0OOOOOOOOOXK000KKKKXNNNNNWNNN
::::::::ccccloddxxxxxxxkkkkkkkkkkkkkkkkkkkkkkxox0NK0OOOOOOOO0XK00KKXKKXNNNNWWWNN
:::::::ccccllodxxxxkkkkkkkkkkkkkkkkkkkkkkkkkkxdx0XK00OOOOOOO0XK0KXNNNXXNNWWWWWWN
:::::::ccccllodxxkkkkkkkkkkkkkkkkkkkkkkkkkxoc;,,;c',:::ldxO00XK0KXNNNNXXNNNWWWWN
:::::::ccccllodxxkkkkkkkkkkkkkkkkkkkkkkko;.              .':dKXKXXXXXKKKXXXNWNNX
:::::::ccccllodxkkkkkkkkkkkkkkkkkkkkkkl.      ..           ..;OKKKK00KKKXXXXNNXX
:::::::ccccllddxkkkkkkkkkkkOOOOOOOOOk:   ...',,,,''......     .lKXKOKKKXXXXXNNXX
:::::::cccllodxxkkkkkkkkkOOOOOOOOOOOo ..:lddxxxdool::;,''..     dXOO0XXXXXNNWWNN
::::::ccccllodxxkkkkkkkkOOOOOOOOOOOO;.,dxkkkkOkxxdocc:;,,'..    :kxOKXXXXNNWMWNN
::::::ccccllodxxkkkkkkOOOOOOOOOOOOOk.,dkkkkkOOkxxdlccc:;;,..    'ldO0KXXXXXWMWXX
:::::::cccllodxkkkkkkOOOOOOOOOOOOOOk.;xkkkkkkkkkxdlc;;;;;,'.    'oxkO00KKXXWMWKK
::::::ccccllodxkkkkkkkkkOOOOOOOOOOO0;,doccokkxkdl;'',,,,,,,'.  .,lxkkkkO00KNWNKK
::::::cccclloooolcccccllodxxkkOOO000O,lldoccokd:,:lo::;;;;;,. .;;,lOOOkkO00KXKKK
::::::ccccc:;;,,;;:cloooooodxkOOOO000ooxdkdokkd;,cdxxdoc:;;,. ,;:,lO00Okkkk0NK00
:::::::::;;,',;::cdk0000OkxlcloOK0O00OlkOOOOOkl;,;oxxdlc:;;'..,'';k000OOkxxOXKOO
:::::::;;;,.;c:cdkk       KOkoccoKX000lk00Odkxo,'',oddl:;;,.  ',;l000O0O00kOKOkO
:::::;;;;,.:l:lo            KOo::c0N00lxOOd:....  ..:lc:;'..  .,:kOO0000OOkOOOOO
::::;;;;,.,o:cd                ol:lXXOcckk','.',.'.. .,,.     .;.  .'o0000Okxxdd
::::;;;;,.:l:    i2p.socket      c:0NOo.;,.:c:::;'...  .     .,;,.  .,d000Okkkxx
::::;;;;,.:c:                   lc:OXOO;......            ..',,',:,',';x000OOOOO
::::;;;;,.,c:lx    (omg)       xl:lKKOOOd,........      ..',,'...','''';xkxxxkOk
:::::;;lollooodok           KKkl::kKOOOOOOd.. ...     ..''''....,''''''':cloloxd
::::::ckk0KK00K00kdoo:dKKKK0Kko:lkOOOOkkkxc,.;k:,,............'''''.''',,:ccloll
::::::lO0K0KK00K00kxo;x0KK0koloxkxddlloo:.;...lc;,',',;..''',''....''',;:;,,,,;c
::::::dO0KxOXXKXk00ko;k0Okdddxxdlc:;cll:,,.'..:oo:'..'','.''.......',;,,,,,;codo
::::lxOO0K0kkkkxxK0xl;clloodxxlc:,;cll:,cc;:dxOo:;;,,;,''.'......',,,,,,,;:cllc:
::::d00O000K00KXK0OkllkkOOOOdcc:,;ccl:,cllcc:kkllcc:;;,,,;'...,;,,,;;;:;;:cllc;:
::cxkOKOOkkkkkOkkxxk:cdkOOOdlcc,:lcl:;cllllc;ld0xl:;,,;,,;;,,c:':::::ccc::lllccl
::ck000000000O00OOkx'..lOOoollc,:llc;llclccc;;lkxxo:;;;:,,,,,;'cccccccccclllllc;
:::lOOOOkkkkO0xxdkkx..'oOocolol;;ll;clccc:cc;,:d0kl;;,,;;;,,,'';,;:cccccllllcc;.
:::lxc;:ccclodddddxl..cko:clool;:ol;cccc::::;,,c,;''co;;;:;;;'..''';cccllllcc;.,
:::::co:;;;,;;:::::,';xll;::lol;clc;:cc:;:;;;;',.',;:lo:;,,;;;'lcc:,,;:lll:c:':c
::::::oOkdocccodoc:,;do:c,cclll;llc::::;;:,,;:'';;;::::cclolcckO0o,'',,;:':c;cll
:::::::lkOkxolcol:,':llcl;:llll:clc::::;:;,,;;,;;;:;::ccc;;:,,coc::;;,,',',;:lll
:::::::ccdxoc:,;;;,,l:cll:,llll:ccc:::;;:;,;;;;;;:;::ccc::c;,,:::::::;;,,,'',;:c
;::::::cclxo:,,;,,';o,:lc;;clcl::c::;;;;;;;;;:cc:;;ccccccccccclolccccc::;;,,,,,,
;::::::c:cdoc;,'''.:l,,:c'':ccc::::;;;;;;;;;;:ll::cccccccccclllllolclcc:::;,,,,,
;;:::::::oxo:,''.'.;c:;,;'.,c::;;;;;;;;;::;;::cc:cccccllolllllcc:collllcc:::;;;;
;;::::::cldoc;'''..',;;,...';;;,;;;;;;::::;:cccc:cccllooollllccc:;:lllcllc::::;;
;;;:::::looo:,,'''..........,,,,,,;;:::::::ccclc:cllllloollllcc:;;;;lllcclcccc::
;;;:::::lolc:;,,,''.  ..... ..'',;;::::ccccclllccllllooollllcc::;;;;;:llcclccccc
;;;::::cllcc;;,,,,'..  ..    .',;;:::ccccccllllclooolooolllllc:;,;:;,'.;:clcc::c
;;;:::;:clcc:;,,,,'' ... .   ..,;:::cccccccldklcooooooollllll:;;;:;;,,..;:::::::
;;;:::,:clc:;,,,,,'......  . ..';:ccclllllllloolooooooooollc:;;;:;;;;,'';:'',;;;
;;;;::.;cc::,,''''.......    ...;::cllllolloooolooooooooolc:;:;;;,;;;,''',;,,,''
;;;;;:..c;;,'''.'..... .... ....,::cllooolloooolooooooollc:::::;;;;,;;,,'',;::::
;..  ,,.c;''.....  .. .....',:l',:cclloollooooloooooollc:;,;;;;;;;;;;;,,,,,,,;;;
.    .;.':,'........,clxkOOOOOOl,:cclloooooooocoooollll:;;:::;;;;;;;;:;,,,,,;;;;
   .. '...';,....':dkkkOOOOOOOOOc:ccllloooodolloolllllc;:cc::;;;;,,,,,,,;;,;;;;;
      ';;;,,';loxxkkkkkkOOOOOOOOklcclllloooxdclolllllc::cc:::::;;;;;,,,,,,;,;;;;
      .',,,',ldddxxkkkkkkOOOOOOOOxccclllollooclllclll::cc:;::::;::;;;,,,,,;,;;;;

Billy Mayes here introducing the automagical i2p.socket python module.

Providing the power of native python sockets that go over i2p via the i2p router
using the i2cp interface. The i2p.socket module implements python standard
standard library's socket module's interface so you can drop in i2p.socket with
as little effort as possible.

    import socket 
    ...

Becomes

    from i2p import socket
    ...

While you still have to use i2p destinations in your code it makes porting your 
python code up to 10 times easier. You can bind multiple incoming destinations,
connect to other destinations from those destinations persisting the destination
Or not, It cam be transient. The power is in your hands.These  i2p sockets can 
be used with the select module as they implement the fileno() method.

BUT WAIT! THERE'S MORE!!

The i2p.socket module comes with an asyncio like interface

    # import it!
    from i2p.socket import async

    # connect it!
    r, w = yield from async.open_connection("psi.i2p", 80)

    # send it!
    w.write(b'GET / HTTP/1.0\r\n')
    _ = yield from w.drain()

    # receive it!
    while True:
      line = yield from r.readline()
      if len(line) > 0:
        print (line)
        continue    
      break
    
    # close it!
    w.close()

All this and more available now on pypi now.

Install today!
"""
