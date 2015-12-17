<%--
  Really basic error page. There are other error pages that are displayed at times,
  but this is a general one which will be displayed if all else fails.
  Date: Aug 5, 2010
  Time: 2:17:49 PM
  Properties included:
  * exception = the exception that generated this page if there is one.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page isErrorPage="true" %>
<%@ include file="assets/includes/start.html" %>

    <h4>There was a problem processing your request.</h4>

    <p>Please check your arguments carefully and try again.</p>

    <p>The diagnostic message reads:</p>
    <p>${exception.message}</p>

<%@ include file="assets/includes/end.html" %>
