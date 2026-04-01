FROM opensuse/tumbleweed:latest

# Base development tools
RUN zypper --non-interactive install \
    git \
    gcc \
    make \
    curl \
    tar \
    xz \
    gzip \
    bzip2 \
    patch \
    which \
    gawk \
    bison \
    flex \
    texinfo \
    help2man \
    unzip \
    autoconf \
    automake \
    libtool \
    python3 \
    && zypper clean --all

# Install Nim via choosenim
RUN curl https://nim-lang.org/choosenim/init.sh -sSf | bash -s -- -y
ENV PATH="/root/.nimble/bin:${PATH}"

# Install crosstool-ng
ARG CTNG_VERSION=1.26.0
RUN cd /tmp \
    && curl -LO "http://crosstool-ng.org/download/crosstool-ng/crosstool-ng-${CTNG_VERSION}.tar.xz" \
    && tar xf "crosstool-ng-${CTNG_VERSION}.tar.xz" \
    && cd "crosstool-ng-${CTNG_VERSION}" \
    && ./configure --prefix=/usr/local \
    && make -j$(nproc) \
    && make install \
    && cd / && rm -rf /tmp/crosstool-ng*

WORKDIR /src
COPY . .

CMD ["nimble", "test"]
