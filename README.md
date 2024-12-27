# HTTP_Reverse_Proxy_Server

This a simple HTTP_Revesr_Proxy_Server that supports HTTP V1.1.

for running this app first you should build it using command "gcc -o proxy-server proxy.c".

because it binds port run it using sudo.

argumesnts you pass to app should be as follow :sudo ./proxy-server --inbound 0.0.0.0:80 --outbound 'target address'.

number of arguments and thier order should be the same.

you can send your requests using curl: curl -H "Host: target address" http://localhost.

and can see the logs by command: curl http://localhost/.svc/collect_logs.
