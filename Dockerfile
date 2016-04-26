FROM ubuntu:14.04

ADD runtests /tmp/
ADD jperms.pl /tmp/
WORKDIR /tmp
CMD /tmp/runtests
