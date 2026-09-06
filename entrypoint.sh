#!/bin/sh
set -e

# dzmedia поднимаем локально, на фиксированном внутреннем порту — наружу
# Render его не видит и не должен: бот дёргает его строго по 127.0.0.1.
# PORT/BIND_ADDR тут заданы ТОЛЬКО для этой команды (в отличие от export),
# поэтому не перебивают $PORT, который Render выставляет для health-check
# сервера ниже в index.js.
PORT=8080 BIND_ADDR=127.0.0.1 ./dzmedia-bin &
DZMEDIA_PID=$!

# Если dzmedia упадёт — не молчим, хотя бы видно будет в логах Render.
( wait "$DZMEDIA_PID"; echo "!!! dzmedia (127.0.0.1:8080) неожиданно завершился, Deezer перестанет работать до редеплоя" ) &

exec node index.js
