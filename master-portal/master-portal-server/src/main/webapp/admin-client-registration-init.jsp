<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<html>

<head>
    <title>Master Portal Administrative Client Registration Page</title>
</head>

<body>
<form action="${actionToTake}" method="post">
    <h2>Welcome to the Master Portal Administrative Client Registration Page</h2>

    <p>This page allows you to register your <b><i>administrative</i></b> client with the
        Master Portal that supports the OpenID-Connect/OAuth2 protocol. To get your client approved,
        please fill out the form below. Your request will be evaluated for approval. For more information,
        please make sure you read the
        <a href="http://grid.ncsa.illinois.edu/myproxy/oauth/client/manuals/registering-with-an-oauth2-server.xhtml"
           target="_blank">Registering a Client with an OAuth 2 server</a> document.
    </p><br>
        <I><B>NOTE:</B> This registration page is <B>ONLY</B> for special
        administrative clients, for a normal client, use the
        <A href="${regularRegEndpoint}">standard registration endpoint</A>.</I>
    </p><br>

    <table>
        <tr>
            <td colspan="2"><b><font color="red"><c:out value="${retryMessage}"/></font></b></td>
        </tr>
        <tr>
            <td>Client Name:</td>
            <td><input type="text" size="25" name="${clientName}" value="<c:out value="${clientNameValue}"/>"/></td>
        </tr>
        <tr>
            <td>Contact email:</td>
            <td><input type="text" size="25" name="${clientEmail}" value="<c:out value="${clientEmailValue}"/>"/></td>
        </tr>
        <tr>
            <td>Issuer (optional):</td>
            <td><input type="text" size="25" name="${issuer}" value="<c:out value="${issuerValue}"/>"/></td>
        </tr>
        <tr>
            <td><input type="submit" value="submit"/></td>
        </tr>
    </table>
    <input type="hidden" id="status" name="${action}"
           value="${request}"/>
</form>
</body>
</html>
