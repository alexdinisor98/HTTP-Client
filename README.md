HTTP Client
Source for JSON parser: https://github.com/zserge/jsmn

The HTTP client I implemented calls the exposed routes of the server, using
GET and POST methods depending on the "message" variable.

The "jsoneq" function helps parsing the response by putting the field content
into static variables.

Depending on the responses, I implemented separate functions for login 
credentials , authorization header using JWT or weather forecast characteristics. 
