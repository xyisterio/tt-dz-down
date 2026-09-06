FROM node:20-slim

# yt-dlp — питоновский, ffmpeg нужен ему для склейки видео+аудио дорожек.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip ffmpeg ca-certificates curl \
    && pip3 install --no-cache-dir --break-system-packages yt-dlp \
    && apt-get purge -y curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev
COPY . .

CMD ["node", "index.js"]
