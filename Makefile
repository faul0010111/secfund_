.PHONY: all install test cov lint fmt type sec demo clean

all: lint type sec cov

install:
	python -m pip install -e ".[dev]"

test:
	python -m unittest discover -s tests

cov:
	coverage run -m unittest discover -s tests
	coverage report

lint:
	ruff check .
	ruff format --check .

fmt:
	ruff check . --fix
	ruff format .

type:
	mypy

sec:
	bandit -q -r secfund -c pyproject.toml

demo:
	python -m secfund logs samples/auth.log --year 2026 --fail-on never
	python -m secfund headers --json-file samples/headers_weak.json --fail-on never

clean:
	rm -rf .coverage htmlcov build dist *.egg-info .mypy_cache .ruff_cache baseline.json
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
