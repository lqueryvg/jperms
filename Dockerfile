FROM ubuntu:14.04

#ADD runtests /tmp/
#ADD jperms.pl /tmp/
#WORKDIR /tmp
#CMD /tmp/runtests

RUN apt-get update -qq && apt-get install -qqy curl
RUN curl -L "http://downloads.sourceforge.net/shunit2/shunit2-2.0.3.tgz" | tar zx -C /tmp

