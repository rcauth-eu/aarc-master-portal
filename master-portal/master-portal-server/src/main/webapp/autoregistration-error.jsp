<%--
  User: Mischa Sallé
  Date: 09-05-2018
  Time: 10:00
  Properties included:
  * error = the error_code
  * exception = the exception that caused this page to be displayed.
--%>
<%@ page contentType="application/json;charset=UTF-8" language="java" %>
{
  "error": "${error}",
  "error_description": "${exception.message}"
}
