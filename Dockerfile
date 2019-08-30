FROM python:3.8-alpine

ENV BUILD_DEPS \
    alpine-sdk \
    coreutils \
    ghc \
    gmp \
    libffi \
    linux-headers \
    musl-dev \
    wget \
    zlib-dev
    
ENV PERSISTENT_DEPS \
    graphviz \
    openjdk8 \
    python \
    py2-pip \
    sed \
    ttf-droid \
    ttf-droid-nonlatin \
    git \
    make 
    
    
ENV EDGE_DEPS cabal

ENV PLANTUML_VERSION 1.2017.18
ENV PLANTUML_DOWNLOAD_URL https://sourceforge.net/projects/plantuml/files/plantuml.$PLANTUML_VERSION.jar/download

ENV PANDOC_VERSION 1.19.2.4
ENV PANDOC_DOWNLOAD_URL https://hackage.haskell.org/package/pandoc-$PANDOC_VERSION/pandoc-$PANDOC_VERSION.tar.gz
ENV PANDOC_ROOT /usr/local/pandoc

# Create Pandoc build space
RUN mkdir -p /pandoc-build
WORKDIR /pandoc-build


# Install/Build Packages
RUN apk upgrade --update && \
    apk add --no-cache --virtual .build-deps $BUILD_DEPS && \
    apk add --no-cache --virtual .persistent-deps $PERSISTENT_DEPS && \
    curl -fsSL "$PLANTUML_DOWNLOAD_URL" -o /usr/local/plantuml.jar && \
    apk add --no-cache --virtual .edge-deps $EDGE_DEPS -X http://dl-cdn.alpinelinux.org/alpine/edge/community && \
    apk del .build-deps .edge-deps


 RUN apk add ca-certificates wget \
  && wget -O /tmp/pandoc.tar.gz https://github.com/jgm/pandoc/releases/download/2.2.3.2/pandoc-2.2.3.2-linux.tar.gz \
  && tar xvzf /tmp/pandoc.tar.gz --strip-components 1 -C /usr/local/ \
  && update-ca-certificates \
  && apk del wget \
  && rm /tmp/pandoc.tar.gz
    
ENV PATH $PATH:$PANDOC_ROOT/bin
RUN which pandoc

RUN git clone https://github.com/izar/pytm /src
WORKDIR /src
RUN cp /usr/local/plantuml.jar /src/.

