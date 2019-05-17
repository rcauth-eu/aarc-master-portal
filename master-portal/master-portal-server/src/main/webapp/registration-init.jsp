<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<html>

<head>
    <title>Master Portal Client Registration Page</title>
</head>

<body>
<form action="${actionToTake}" method="post">
    <h2>Welcome to the Master Portal Client Registration Page</h2>

    <p>This page allows you to register your client with the
        Master Portal that supports the OpenID-Connect/OAuth2 protocol. To get your client approved,
        please fill out the form below. Your request will be evaluated for approval. For more information,
        please make sure you read the
        <a href="http://grid.ncsa.illinois.edu/myproxy/oauth/client/manuals/registering-with-an-oauth2-server.xhtml"
           target="_blank">Registering a Client with an OAuth 2 server</a> document.
    </p><br>
    <table>
        <tr>
            <td>Client Name:</td>
            <td><input type="text" size="25" name="${clientName}" value="${clientNameValue}"/></td>
        </tr>
<%--    <tr style="vertical-align: top">
            <td>Client Description:</td>
            <td>
                <textarea id="${clientDescription}" rows="10" cols="80"
                          name="${clientDescription}">${clientDescriptionValue}</textarea>
            </td>
        </tr>--%>
        <tr>
            <td>Contact email:</td>
            <td><input type="text" size="25" name="${clientEmail}" value="${clientEmailValue}"/></td>
        </tr>
        <tr>
            <td>Home URL:</td>
            <td><input type="text" size="25" name="${clientHomeUrl}" value="${clientHomeUrlValue}"/></td>
        </tr>
        <tr>
            <td ${rtFieldVisible}>Refresh Token lifetime:</td>
            <td ${rtFieldVisible}><input type="text" size="25" name="${rtLifetime}" value="${rtLifetimeValue}"/>(in
                seconds - leave blank for no refresh tokens.)
            </td>
        </tr>
        <tr>
            <td><span title="Check this box to receive limited proxy certificates. Leave unchecked for normal proxies.">
            Receive only limited proxies:</span></td>
            <td><input type="checkbox" name="${clientProxyLimited}" ${clientProxyLimitedValue} />
            </td>
        </tr>
<%--    <tr>
            <td>Issuer (optional):</td>
            <td><input type="text" size="25" name="${issuer}" value="${issuerValue}"/></td>
        </tr>--%>
<%--    <tr style="vertical-align: top">
            <td><span title="Check this box if the client is to be public, i.e., limited access, no certificates allowed and no secret needed. If you are not sure what this is, do not check it or ask for help.">
            Is this client public?<br><em>Then only openid scope is allowed</em></span></td>
            <td><input type="checkbox" name="${clientIsPublic}" ${clientIsPublicValue} />
            </td>
        </tr>--%>

        <tr style="vertical-align: top">
            <td>Callback URLs:</td>
            <td>
                <textarea id="${callbackURI}" rows="10" cols="80"
                          name="${callbackURI}">${callbackURIValue}</textarea>
            </td>
        </tr>
        <tr style="vertical-align: top">
            <td>Scopes:</td>
            <td><c:forEach items="${scopes}" var="scope">
                    <input type="checkbox"
                           name="chkScopes"
                           value="${scope}"<c:set var="xxx" scope="session" value="${scope}"/><c:if test="${xxx == 'openid'}"> checked="checked"</c:if>>${scope}<br></c:forEach>
            </td>
        </tr>
        <tr>
            <td><input type="submit" value="submit"/></td>
        </tr>
        <tr>
            <td colspan="2"><b><font color="red">${retryMessage}</font></b></td>
        </tr>
    </table>
    <input type="hidden" id="status" name="${action}"
           value="${request}"/>
</form>
</body>
</html>
