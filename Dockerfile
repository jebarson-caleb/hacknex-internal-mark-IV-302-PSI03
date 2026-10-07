FROM node:26-bookworm-slim AS ui
WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
COPY backend/ /app/backend/
RUN python -m pip install --no-cache-dir -r backend/requirements.lock && python -m pip install --no-cache-dir --no-deps -e backend
COPY --from=ui /build/frontend/dist /app/frontend/dist
COPY scripts/run_demo.py /app/scripts/run_demo.py
ENV TRACEGUARD_DB=/app/runtime/traceguard.sqlite3
RUN mkdir /app/runtime && useradd --uid 10001 --create-home traceguard && chown -R traceguard:traceguard /app/runtime
USER traceguard
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "traceguard.main:app", "--host", "0.0.0.0", "--port", "8000"]
