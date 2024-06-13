
FROM python:3.12-rc-alpine


WORKDIR /usr/src/app
ENTRYPOINT ["sh"]

ENV PLANTUML_VER 1.2021.7
ENV PLANTUML_PATH /usr/local/lib/plantuml.jar
ENV PANDOC_VER 2.14.0.1

RUN apk add --no-cache graphviz openjdk11-jre fontconfig make curl ttf-liberation ttf-linux-libertine ttf-dejavu \
    && apk add --no-cache --virtual .build-deps gcc musl-dev \
    && rm -rf /var/cache/apk/* \
    && curl -LO https://master.dl.sourceforge.net/project/plantuml/$PLANTUML_VER/plantuml.$PLANTUML_VER.jar \
    && mv plantuml.$PLANTUML_VER.jar $PLANTUML_PATH \
    && curl -LO https://github.com/jgm/pandoc/releases/download/$PANDOC_VER/pandoc-$PANDOC_VER-linux-amd64.tar.gz \
    && tar xvzf pandoc-$PANDOC_VER-linux-amd64.tar.gz --strip-components 1 -C /usr/local/

ENV _JAVA_OPTIONS -Duser.home=/tmp -Dawt.useSystemAAFontSettings=gasp
RUN printf '@startuml\n@enduml' | java -Djava.awt.headless=true -jar $PLANTUML_PATH -tpng -pipe >/dev/null

COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt \
    && apk del .build-deps

COPY pytm ./pytm
COPY docs ./docs
COPY *.py Makefile ./
