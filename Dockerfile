# Scegli un'immagine Node.js di base  
FROM node:20-slim
ARG CACHE_BUST=23
RUN echo "Cache bust: $CACHE_BUST"

# Installa python3, pip e dipendenze per compilazione  
USER root 
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    build-essential ca-certificates \
    tesseract-ocr tesseract-ocr-ita tesseract-ocr-eng \
    libtesseract-dev libleptonica-dev \
    && rm -rf /var/lib/apt/lists/*

# Crea un symlink per python (importante!)
RUN ln -s /usr/bin/python3 /usr/bin/python

# Imposta la directory di lavoro nell'immagine
WORKDIR /usr/src/app

# Installa le dipendenze Python necessarie (inclusi OCR e curl_cffi)
RUN pip3 install --no-cache-dir --break-system-packages \
    requests beautifulsoup4 pycryptodome pyDes \
    pillow pytesseract curl_cffi fake-headers lxml

# Installa una versione specifica di pnpm per evitare problemi di compatibilità della piattaforma
RUN npm install -g pnpm@8.15.5

# Copia i file del progetto nella directory di lavoro
COPY . .

# Copy files (owned by root initially)
COPY . .

# IMPORTANTE: Imposta le variabili d'ambiente per Python
ENV PYTHONPATH=/usr/local/lib/python3.11/dist-packages:/usr/lib/python3.11/dist-packages
ENV PATH="/usr/local/bin:/usr/bin:$PATH"

# Pulisci cache precedenti e installa dipendenze come ROOT per evitare problemi di permessi
ARG BUILD_CACHE_BUST=23
RUN echo "Build cache bust: $BUILD_CACHE_BUST"
# Usa store globale o default, non importa, siamo root ora
ENV NPM_CONFIG_STORE_DIR=/usr/src/app/.pnpm-store

RUN rm -rf node_modules .pnpm-store dist 2>/dev/null || true
RUN pnpm install --prod=false

# Fix per il problema undici su ARM/Raspberry Pi
RUN pnpm add undici@6.19.8

# Esegui il build dell'applicazione TypeScript
RUN pnpm run build

# ORA impostiamo i permessi corretti per l'esecuzione
RUN chown -R node:node /usr/src/app

# Torna all'utente node per l'esecuzione
USER node

# Fix per il problema undici su ARM/Raspberry Pi
RUN pnpm add undici@6.19.8

# Esegui il build dell'applicazione TypeScript
RUN pnpm run build


# Avvio diretto dell'addon (lo script wrapper /start per Beamup non serve più)
ENTRYPOINT ["node", "dist/addon.js"]
