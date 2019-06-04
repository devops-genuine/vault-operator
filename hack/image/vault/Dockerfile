FROM vault:1.1.2

RUN apk --no-cache add curl
RUN setcap cap_ipc_lock=+ep $(readlink -f $(which vault))
