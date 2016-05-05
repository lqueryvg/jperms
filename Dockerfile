# Used for local testing with Docker
#

FROM ubuntu:14.04

RUN apt-get update -qq && apt-get install -qqy curl
RUN curl -L "http://downloads.sourceforge.net/shunit2/shunit2-2.0.3.tgz" | tar zx -C /tmp

