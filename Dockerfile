FROM python:3.11-slim
WORKDIR /agent
COPY . /agent
CMD ["python", "agent.py"]