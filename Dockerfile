# Stage 1: Builder
FROM python:3.9-alpine

WORKDIR /checker

# Install required packages and locate the binaries
RUN apk add --no-cache iputils curl bind-tools net-tools netcat-openbsd

# Copy the Python script and requirements file
COPY test_script.py requirements.txt /checker/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Python and create a symlink for python3
RUN apk add --no-cache python3 && \
    ln -sf python3 /usr/bin/python

# Set Environment Variables
ENV POD_NETWORK_RANGE=172.0.0.0/8 \
    NAMESPACE=default \
    NETCHECK_SVC_NAME=netCheck

# Expose port 8080
EXPOSE 8080

# Set the script to be executable and run it
WORKDIR /checker
RUN chmod +x test_script.py
CMD ["python", "./test_script.py"]
