setup:
	@echo "[Log] Installing system dependencies for Python development."
	@echo "[Log] Installing python3-dev package..."
	sudo apt-get install python3-dev -y
	@echo "[Log] python3-dev package installed successfully."

	@echo "[Log] Installing python3-pip package..."
	sudo apt-get install python3-pip -y
	@echo "[Log] python3-pip package installed successfully."

	@echo "[Log] Installing project dependency manager."
	@echo "[Log] Installing pip and setuptools packages..."
	pip3 install -U pip setuptools
	@echo "[Log] Installed pip and setuptools packages successfully"

	@echo "[Log] Installing virtualenv project dependency..."
	pip3 install -U virtualenv
	@echo "[Log] virtualenv dependency installed successfully."

	@echo "[Log] Creating project virtual environment..."
	virtualenv --no-site-packages ./venv
	@echo "[Log] Successfully created virtual environment"

update:
	( \
	. venv/bin/activate; \
	pip3 install -r requirements.txt; \
	)
