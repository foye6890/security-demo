<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html>
<head>
    <title>Hello</title>
</head>
<body>
    <h1>Hello, ${pageContext.request.userPrincipal.name}!</h1>
    <a href="/logout">Logout</a>
</body>
</html>