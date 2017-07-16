# ACID	![Acid][logo]
An application for initial setup and configuration of Cisco ACI (Application Centric Infrastructure)


-----------------------------------------
####   VERSION   ####

The version of **Acid** documented here is: **v1.0.0**


-----------------------------------------
####   TABLE OF CONTENTS   ####

1. [What is Acid?](#what-is-acid)
2. [Requirements](#requirements)
3. [Screenshots](#screenshots)
4. [Compile](#compile)
5. [Contributing](#contributing)


-----------------------------------------
####   WHAT IS ACID   ####

The initial setup of ACI can be a painful and confusing process due to the overwhelming use of object-oriented configurations and the many steps needed to perform a baseline setup. Using the raw API with something like PostMan is not much better. Acid is designed to get you through that process quickly and painlessly.


--------------------------------------
####   REQUIREMENTS   ####

OS:			**Windows, Linux, and MacOS** are supported and pre-compiled binaries are provided in the "Binaries" folder on the [Github][github_acid] repo

Interpreter:		**Python 2.7.13+ and 3.6.X** are compatible with the Acid source, but an interpreter is not required if you use the binaries.


--------------------------------------
####  SCREENSHOTS  ####

**The Acid main window**
![Acid][main-window]

**The Acid basic settings window**
![Acid][basic-settings-window]

**The Acid port configuration window**
![Acid][ports-window]


--------------------------------------
####   COMPILE   ####
Acid requires the use of Python 2.7.13 (or later) or 3.6.X due ACI's requirement for SSL TLS1.2 which is not included in older Python SSL libraries.

##### Windows
  1. Install Python 2.7.13+ or Python 3.6.X interpreter from the [Python Website][python_website]
  2. Download "pip-Win" from its [download site][pip_win]
  3. Open pip-Win and run with command `venv -c -i  pyi-env-name`
  4. Install PyInstaller with command `pip install PyInstaller`
  5. Navigate a folder with acid.py and acid.ico files
  6. Run command to compile: `pyinstaller --onefile --windowed --icon=acid.ico --clean Acid.py`

##### MacOS/Linux
  1. Install Python 2.7.13 and set as default interpreter
	  - Install [Homebrew][homebrew]
	  - Open Terminal and use Homebrew to install updated Python: `brew install python`
	  - Open the bash_profile in VI and add the new Python path: `more .bash_profile`
	    - Insert the line at the bottom: `export PATH="/usr/local/Cellar/python/2.7.13/bin:${PATH}"`
	  - Close Terminal and reopen it, type `python --version` and make sure it shows version 2.7.13 or greater
  2. Install Pip with command `sudo easy_install pip`
  3. Use Pip to install PyInstaller `pip install pyinstaller`
  4. Run command to compile: `pyinstaller --onefile --windowed --icon=acid.ico --clean Acid.py`


--------------------------------------
####   CONTRIBUTING   ####

If you would like to help out by contributing code or reporting issues, please do!

Visit the GitHub page (https://github.com/PackeTsar/acid) and either report an issue or fork the project, commit some changes, and submit a pull request.


--------------------------------------
[logo]: http://www.packetsar.com/wp-content/uploads/acid-logo-tiny-100.png
[github_acid]: https://github.com/PackeTsar/acid
[python_website]: https://www.python.org/
[pip_win]: https://sites.google.com/site/pydatalog/python/pip-for-windows
[homebrew]: https://brew.sh/
[main-window]: http://www.packetsar.com/wp-content/uploads/acid-main.png
[basic-settings-window]: http://www.packetsar.com/wp-content/uploads/acid-basic.png
[ports-window]: http://www.packetsar.com/wp-content/uploads/acid-ports.png
