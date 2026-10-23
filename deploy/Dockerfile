FROM python:3.12-slim
RUN useradd --system --uid 10001 lump
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir '.[host]'
USER lump
EXPOSE 8080
ENTRYPOINT ["lump"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
