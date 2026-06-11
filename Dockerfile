FROM python:3.13.5-slim
WORKDIR /artifact
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash poppler-utils \
    texlive-latex-base texlive-latex-extra texlive-fonts-recommended texlive-bibtex-extra \
    && rm -rf /var/lib/apt/lists/*
COPY . /artifact
RUN pip install --no-cache-dir -r requirements.txt
ENV MPLBACKEND=Agg PYTHONHASHSEED=0
CMD ["bash", "run_all.sh"]
