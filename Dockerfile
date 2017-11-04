from ubuntu:latest

# BUILD THE PAM MODULE
RUN apt-get update && \
    apt-get -y install automake build-essential libpam0g-dev libssl-dev

RUN mkdir -p /build

COPY ./makefile /build/
COPY ./src /build/src

RUN cd /build && \
    make && make install

RUN apt-get -y remove automake build-essential && \
    apt-get -y autoremove && \
    rm -rf /build

RUN useradd -Um noob && printf "noob\nnoob" | passwd noob
COPY ./common-auth /etc/pam.d/
COPY ./hmac_secret /home/noob/.hmac_secret
