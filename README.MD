Spring Boot Security practise with JWT.

https://auth0.com/blog/securing-spring-boot-with-jwts/

Step 1 :

http://localhost:1002/login
POST : {"username":"admin","password":"password"}


In the response to this request, we will get a token as part of the Authorization header, prefixed by "Bearer".
We can copy this token, with the Bearer prefix, to issue GET requests to our /users path. To do this, alter the request to /users to include a header called Authorization, paste the JWT received when logging in, and launch the request.
If all went well, we should once again be presented with the users.

WebSecurityConfig is the main class.