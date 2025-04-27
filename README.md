# ZJUWebVPNSession

A Python wrapper for accessing **Zhejiang University WebVPN** automatically.  
Login once, access all ZJU internal sites as if you are on campus.

[![Build and Release](https://github.com/eWloYW8/ZJUWebVPN/actions/workflows/release.yml/badge.svg)](https://github.com/eWloYW8/ZJUWebVPN/actions/workflows/release.yml)

## Features
- Auto login to [webvpn.zju.edu.cn](https://webvpn.zju.edu.cn)
- Transparent URL conversion (no need to manually rewrite URLs)
- Fully compatible with [`requests`](https://docs.python-requests.org/en/latest/) API
- Easy to download files, submit forms, crawl internal resources, etc.

## Install
```bash
pip install ZJUWebVPN
```

## Quick Start

```python
from ZJUWebVPN import ZJUWebVPNSession

# Create a session and login
session = ZJUWebVPNSession('your_zju_username', 'your_zju_password')

# Example: GET request to an internal site
resp = session.get('https://www.cc98.org/')
print(resp.text)
```

## Examples

### 1. GET a page

```python
resp = session.get('https://www.cc98.org/')
print(resp.text)
```

### 2. POST a form

```python
data = {'key1': 'value1', 'key2': 'value2'}
resp = session.post('https://test.zju.edu.cn/submit', data=data)
print(resp.text)
```

## Requirements
- `requests`
- `pycryptodome`

