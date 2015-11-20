<%--
  User: Jeff Gaynor
  Date: 9/27/11
  Time: 4:37 PM

  NOTE:This page is supplied as an example and under no circumstances should ever be deployed
  on a live server. It is intended to show control flow as simply as possible.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<link rel="stylesheet" type="text/css" media="all"
      href="static/demo.css"/>
<head><title>Master Portal OAuth 2 client error page</title></head>
<body>
<body>

<br clear="all"/>

<div class="main">

    <H2>There was a problem getting the cert.</H2>

    Check the server logs...

    <form name="input" action="${action}" method="get"/>
    <input type="submit" value="Return to client"/>
    </form>


    <br><br> The error code was:${error}
    <br><br>Error description:${error_description}
    <br><br>Error uri:${error_uri}
</div>
</body>
</html>