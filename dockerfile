FROM telegraf:1.28.5

LABEL maintainer="khacman98@gmail.com"

ENV USER=root

RUN apt update && apt install nano htop -y

ADD --chown=${USER}:${USER} --chmod=775  ./nginx2commonlog /usr/bin/
ADD --chown=${USER}:${USER} --chmod=775 entrypoint.sh /
