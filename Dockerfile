FROM python:3.7-bullseye
COPY entrypoint.py /entrypoint.py
CMD ["python", "-u", "/entrypoint.py"]
