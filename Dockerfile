FROM ubuntu:22.04

RUN apt-get update
RUN apt-get install -y net-tools iproute2 python3 python3-pip
RUN pip install tcconfig
RUN apt-get install -y build-essential curl vim

WORKDIR /home

RUN export RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static && \
    export RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

COPY ./aes /home/aes
COPY ./network /home/network
COPY ./okvs /home/okvs
COPY ./ot /home/ot
COPY ./sa /home/sa
COPY ./utils /home/utils
COPY ./vole /home/vole
COPY ./vole_f2k /home/vole_f2k
COPY ./Cargo.toml /home/Cargo.toml
COPY ./README.md /home/README.md
COPY ./build_cmd.sh /home/build_cmd.sh

RUN export PATH="$HOME/.cargo/bin:$PATH" && \
    chmod +x /home/build_cmd.sh &&\
    ./build_cmd.sh

COPY ./run_bench.sh /home/run_bench.sh
RUN chmod +x /home/run_bench.sh






