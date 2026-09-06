FROM node:20-slim

# ADD с URL инвалидирует кэш слоя сам, когда меняется содержимое ответа —
# PyPI отдаёт метаданные последнего релиза yt-dlp, так что при каждой
# пересборке после выхода новой версии этот слой (и следующий pip install)
# пересоберётся заново, а не возьмётся из кэша со старым yt-dlp. Это важно:
# TikTok регулярно меняет защиту от ботов, и без свежего yt-dlp скачивание
# начинает падать с ошибками вида "Unexpected response from webpage
# request" — чинится обновлением yt-dlp, а не правкой кода бота.
ADD https://pypi.org/pypi/yt-dlp/json /tmp/yt-dlp-version.json

# yt-dlp — питоновский, ffmpeg нужен ему для склейки видео+аудио дорожек.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip ffmpeg ca-certificates curl \
    && pip3 install --no-cache-dir --break-system-packages -U yt-dlp \
    && apt-get purge -y curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev
COPY . .

CMD ["node", "index.js"]
