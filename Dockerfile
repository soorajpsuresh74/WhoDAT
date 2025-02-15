From python:3.10
WORKDIR /who_dat_app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 5000 5001
CMD ["python", "setup.py"]
