# tatou
A web platform for pdf watermarking. This project is intended for pedagogical use, and contain security vulnerabilities. Do not deploy on an open network.

## Instructions

The following instructions are meant for a bash terminal on a Linux machine. If you are using something else, you will need to adapt them.

To clone the repo, you can simply run:

```bash
git clone https://github.com/olosva/tatou.git
```

Note that you should probably fork the repo and clone your own repo.


### Run python unit tests

```bash
cd tatou/server

# Create a python virtual environement
python3 -m venv .venv

# Activate your virtual environement
source .venv/bin/activate

# Install the necessary dependencies
python -m pip install -e ".[dev]"

# Run all tests
pytest -q
```
# Run Coverage analysis
pytest -q --cov=src --cov-branch --cov-report=term-missing --cov-report=html:htmlcov

# Open Coverage analysis in http://localhost:8000
python -m http.server --directory (Path way to the file) 8000

### Deploy

From the root of the directory:

```bash
# Create a file to set environement variables like passwords.
cp .env.example .env

# Edit .env and pick the passwords you want

# Rebuild the docker image and deploy the containers
docker compose up --build -d

# Monitor logs in realtime 
docker compose logs -f

# Test if the API is up
curl -i http://127.0.0.1:5000/healthz

# Open your browser at 127.0.0.1:5000 to check if the website is up.
```



