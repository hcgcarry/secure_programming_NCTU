FROM ubuntu:20.04

MAINTAINER K1a <kia@csie.io>

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y xinetd

RUN adduser --disabled-password --gecos ""  filenote_x

COPY ./filenote_x /home/filenote_x
COPY ./xinetd /etc/xinetd.d/filenote_x

RUN chown -R root:root /home/filenote_x
RUN chmod -R 755 /var/tmp
RUN chmod -R 774 /dev
RUN chmod -R 774 /run

CMD ["/usr/sbin/xinetd","-dontfork"]
