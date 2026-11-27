# Imagem de PARIDADE: Python (original) + Rust (port) no MESMO filesystem e PATH.
# Isso não é preferência de estilo: /health detecta ferramentas com `which <tool>`,
# então os dois lados só podem ser comparados se enxergarem o mesmo PATH.
FROM kalilinux/kali-rolling:latest
ENV DEBIAN_FRONTEND=noninteractive
# Dependências Python vindas do apt (o header do monólito importa selenium e
# mitmproxy no load do pacote, então eles são obrigatórios para subir o server).
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-flask python3-psutil python3-requests python3-aiohttp \
      python3-bs4 python3-selenium mitmproxy \
      rustc cargo build-essential pkg-config \
      nmap gobuster sqlmap nikto dirb hydra john hashcat \
      curl jq ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
