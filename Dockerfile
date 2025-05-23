# 1) Pick a base image that has Python 3.9 (so your tensorflow-cpu==2.10.1 wheel exists)
FROM python:3.9-slim

# 2) Set a working directory
WORKDIR /app

# 3) Copy only requirements first (leverages Docker cache)
COPY requirements.txt ./

# 4) Install system deps & Python libs
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc curl \
 && pip install --upgrade pip \
 && pip install -r requirements.txt \
 && apt-get purge -y --auto-remove gcc \
 && rm -rf /var/lib/apt/lists/*

# 5) Copy your entire Rasa project into the image
COPY . .

# 6) Expose the ports Rasa & the action server listen on
EXPOSE 5005 5055

# 7) Start both Rasa and the action server in one go
#    The first process (&) backgrounds the core server, then the SDK server runs in foreground
CMD [ "bash", "-lc", "\
    rasa run --enable-api --cors \"*\" --debug & \
    rasa run actions --actions actions" ]
