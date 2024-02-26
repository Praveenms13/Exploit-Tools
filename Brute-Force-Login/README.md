# Brute Force Login Tool

![GitHub repo size](https://img.shields.io/github/repo-size/Praveenms13/Brute-Force-Login?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

## Overview

This is a simple Brute Force Login tool written in Python. It is designed to assist in testing the security of login forms or API login endpoints. The tool supports both GET and POST HTTP methods for brute force attacks and gives results based on the retrieved status code.

## Prerequisites

- Python3
- PIP

![Python Version](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge)
![GitHub top language](https://img.shields.io/github/languages/top/Praveenms13/Brute-Force-Login?style=for-the-badge)
![GitHub language count](https://img.shields.io/github/languages/count/Praveenms13/Brute-Force-Login?style=for-the-badge)
![GitHub last commit](https://img.shields.io/github/last-commit/Praveenms13/Brute-Force-Login?color=red&style=for-the-badge)
![Visitors](https://api.visitorbadge.io/api/visitors?path=https%3A%2F%2Fgithub.com%2FPraveenms13%2FBrute-Force-Login&countColor=%23263759)

![GitHub stars](https://img.shields.io/github/stars/Praveenms13/Brute-Force-Login?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/Praveenms13/Brute-Force-Login?style=social)

## Features

- **Form Analysis:** Extracts and analyzes HTML form attributes to identify input names for username and password fields, extracts the `type` of an input tag or button tag, also extracts all the required tokens, cookies for a login session.

<p align="center">
  <img width="80%" src="img/inp.jpg" alt="Centered Image">
</p>

- **Wordlist Attack:** Supports username and password brute force attacks using a provided wordlist file.
- **GET and POST Methods:** Choose between GET and POST methods based on the target's login mechanism.
- **Cookie Support:** Optionally provide a cookie value for authentication.
- **User-friendly Interface:** Provides clear and colored console output for better user interaction.

## Installation (Release from PyPI)

[![PyPI Version](https://img.shields.io/pypi/v/brute-force-attacker?style=for-the-badge&logo=PyPI&logoColor=white)](https://pypi.org/project/brute-force-attacker/) [![Supported OS](https://img.shields.io/badge/Works%20on-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://en.wikipedia.org/wiki/Linux)



Install the `brute-force-attacker` package using pip:
Find the latest release on <a href="https://pypi.org/project/brute-force-attacker/">PyPI</a>.

```bash
pip install brute-force-attacker
```


### Run as command line tool

```
brute -w <wordlist_file> -t <target_url> -m <http_method> [-u <username>] [-c <cookie_value>]
```

- `-t` or `--target`: Specify the target URL.
- `-w` or `--wordlist`: Specify the wordlist file.
- `-m` or `--method`: Specify the HTTP method (get or post).

Optional arguments:

- `-u` or `--username`: Specify the username for targeted brute force (optional).
- `-c` or `--cookie`: Specify the cookie value for authentication (optional).

## Help Menu
<p align="center">
  <img width="80%" src="img/help.jpeg" alt="Centered Image">
</p>

## Tool Usage (GET)

### 1. Brute Force Login using GET with Username


```
brute -w word1.txt -t "https://forms.praveenms.site/login.php?username=admin&password=" -m GET
```

### 2. Brute Force Login using GET with Username


```
brute -w word2.txt -t "https://forms.praveenms.site/login.php?username=&password=" -m GET
```
<hr>

## Tool Usage (POST)

### 1. Brute Force Login using POST with username

```
brute -w word1.txt -u admin -t "https://forms.praveenms.site/login.php" -m POST
```

### 2. Brute Force Login using POST without username

```
brute -w word2.txt -t "https://forms.praveenms.site/login.php" -m POST
```
<hr>



## Scren Shots

<p align="center">
  <img width="80%" src="img/ss.jpg" alt="Centered Image">
</p>

<hr>

## Disclaimer

This tool is intended for educational and testing purposes only. Unauthorized access to systems or networks without permission is illegal.

## License 

![](https://img.shields.io/badge/license-MIT-green) 

 <a href="https://choosealicense.com/licenses/mit/">MIT</a>

### Target Site: https://forms.praveenms.site/login.php

The above site is used to test the Brute force login


## Social Media Links: 

<a href="https://www.instagram.com/praveen.ms_13/">
  <img src="https://img.shields.io/badge/Instagram-E4405F?style=for-the-badge&logo=instagram&logoColor=white" alt="Instagram">
</a><a href="https://www.linkedin.com/in/m-s-praveen-kumar-2243b622a/">
  <img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn">
</a><a href="https://github.com/Praveenms13">
  <img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub">
</a><a href="https://www.praveenms.site/">
  <img src="https://img.shields.io/badge/Portfolio-%23000000.svg?style=for-the-badge&logo=firefox&logoColor=#FF7139" alt="GitHub">
</a>