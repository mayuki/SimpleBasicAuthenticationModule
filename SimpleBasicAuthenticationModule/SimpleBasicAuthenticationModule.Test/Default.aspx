<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="SimpleBasicAuthenticationModule.Test._Default"%><%@ Import Namespace="System.Security.Principal"
%><!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" >
<head runat="server">
<title>SimpleBasicAuthenticationModule</title>
</head>
<body>
<form id="form1" runat="server">
<dl>
<dt>User.Identity.GetType()</dt><dd><%= HttpUtility.HtmlEncode(User.Identity.GetType().ToString()) %></dd>
<dt>User.Identity.Name</dt><dd><%= HttpUtility.HtmlEncode(User.Identity.Name) %></dd>
<dt>User.Identity.AuthenticationType</dt><dd><%= HttpUtility.HtmlEncode(User.Identity.AuthenticationType) %></dd>
<dt>User.IsInRole("User")</dt><dd><%= HttpUtility.HtmlEncode(User.IsInRole("User").ToString()) %></dd>
<dt>User.IsInRole("Manager")</dt><dd><%= HttpUtility.HtmlEncode(User.IsInRole("Manager").ToString()) %></dd>
<dt>User.IsInRole("Administrator")</dt><dd><%= HttpUtility.HtmlEncode(User.IsInRole("Administrator").ToString()) %></dd>
</dl>
</form>
</body>
</html>
