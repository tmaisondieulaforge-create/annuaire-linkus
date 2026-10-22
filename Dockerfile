FROM python:3.12-alpine

WORKDIR /app

# Installation des dépendances pour le chiffrement AES-256
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie des fichiers applicatifs
COPY server.py .
COPY static ./static

# Variable d'environnement pour le port (compatible Render, Railway, Fly.io, Cloud)
ENV PORT=5000
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

# Commande de démarrage
CMD ["python", "server.py"]
