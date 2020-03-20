FROM rust:latest

RUN apt update \
    && apt install -y tcpdump \
    && mkdir /usr/local/rusdhcp

WORKDIR /usr/local/rusdhcp
CMD ["/bin/bash"]
