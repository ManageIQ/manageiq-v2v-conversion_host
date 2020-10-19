FROM alpine:3.8

ENV OPERATOR=/usr/local/bin/vm-import-provider \
    USER_UID=1001 \
    USER_NAME=vm-import-provider

# install operator binary
COPY build/_output/bin/vm-import-provider ${OPERATOR}

COPY build/bin /usr/local/bin
RUN  /usr/local/bin/user_setup

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER ${USER_UID}
