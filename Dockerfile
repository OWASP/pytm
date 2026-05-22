FROM python:3.14.4-alpine3.23

WORKDIR /app
ENTRYPOINT ["/app/entrypoint.sh"]

ENV PLANTUML_VER=1.2026.2
ENV PLANTUML_PATH=/usr/local/lib/plantuml.jar
ENV PANDOC_VER=2.19.2

RUN apk add --no-cache graphviz openjdk11-jre fontconfig make curl ttf-liberation ttf-linux-libertine ttf-dejavu \
    && apk add --no-cache --virtual .build-deps gcc musl-dev \
    && rm -rf /var/cache/apk/* \
    && curl -LO https://github.com/plantuml/plantuml/releases/download/v$PLANTUML_VER/plantuml-mit-$PLANTUML_VER.jar \
    && mv plantuml-mit-$PLANTUML_VER.jar $PLANTUML_PATH \
    && curl -LO https://github.com/jgm/pandoc/releases/download/$PANDOC_VER/pandoc-$PANDOC_VER-linux-amd64.tar.gz \
    && tar xvzf pandoc-$PANDOC_VER-linux-amd64.tar.gz --strip-components 1 -C /usr/local/

ENV _JAVA_OPTIONS=-Duser.home=/tmp -Dawt.useSystemAAFontSettings=gasp
RUN printf '@startuml\n@enduml' | java -Djava.awt.headless=true -jar $PLANTUML_PATH -tpng -pipe >/dev/null

COPY pyproject.toml ./
COPY pytm ./pytm
COPY docs ./docs
COPY *.py Makefile entrypoint.sh ./

RUN pip install poetry \
    && poetry config virtualenvs.create false \
    && poetry install
