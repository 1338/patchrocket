FROM patchrocket-worker:local
WORKDIR /fixture
COPY composer.json composer.lock ./
COPY src src
COPY public public
COPY vendor vendor
USER 65534:65534
HEALTHCHECK --interval=2s --timeout=2s CMD ["php", "-r", "exit(@file_get_contents('http://127.0.0.1:8080/') === false ? 1 : 0);"]
CMD ["php", "-S", "127.0.0.1:8080", "-t", "public"]
