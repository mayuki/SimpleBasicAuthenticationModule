using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using Misuzilla.Web.Configuration;

namespace Misuzilla.Web.Security
{
    public class SimpleBasicAuthenticationModule : BasicAuthenticationModuleBase
    {
        private Dictionary<String, SimpleBasicAuthenticationUserElement> _users;
        private List<Regex> _exceptPaths;
        private Boolean _setUser = true;

        #region IHttpModule メンバ

        public override void Init(HttpApplication context)
        {
            if (!GetSection().Enabled)
                return;

            base.Init(context);

            _users = new Dictionary<String, SimpleBasicAuthenticationUserElement>();
            foreach (SimpleBasicAuthenticationUserElement user in GetSection().Users)
            {
                _users[user.Name] = user;
            }

            _exceptPaths = new List<Regex>();
            foreach (SimpleBasicAuthenticationExceptPathElement exceptPath in GetSection().ExceptPaths)
            {
                _exceptPaths.Add(new Regex(exceptPath.UseRegex ? exceptPath.Path : "^"+Regex.Escape(exceptPath.Path)));
            }
        }

        #endregion
        
        private SimpleBasicAuthenticationSection GetSection()
        {
            var sect = System.Web.Configuration.WebConfigurationManager.GetSection(SimpleBasicAuthenticationSection.SectionName);
            SimpleBasicAuthenticationSection authSection = sect as SimpleBasicAuthenticationSection;
            return authSection;
        }

        protected override bool IsSetUser(HttpContextBase ctx)
        {
            return GetSection().SetUser;
        }

        protected override bool IsAuthenticateRequired(HttpContextBase ctx)
        {
            return _exceptPaths.TrueForAll(x => !x.IsMatch(ctx.Request.Path));
        }
        
        protected override IPrincipal Authenticate(String userName, String password)
        {
            if (_users.ContainsKey(userName))
            {
                SimpleBasicAuthenticationUserElement userElement = _users[userName];
                Boolean isAuthenticated = false;
                switch (userElement.Type)
                {
                    case PasswordEncodeType.ClearText:
                        isAuthenticated = (userElement.Password == password);
                        break;
                    case PasswordEncodeType.SHA1:
                        isAuthenticated = (userElement.Password == GetHashDigest(SHA1.Create(), password));
                        break;
                    case PasswordEncodeType.MD5:
                        isAuthenticated = (userElement.Password == GetHashDigest(MD5.Create(), password));
                        break;
                }

                if (isAuthenticated)
                {
                    return new GenericPrincipal(new GenericIdentity(userName, "Basic"),
                                                userElement.Roles.Split(new[] {','}, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).ToArray());
                }
            }
            return null;
        }

        protected override string GetRealm(HttpContextBase ctx)
        {
            return GetSection().Realm;
        }
    
        private static String GetHashDigest(HashAlgorithm hashAlgorithm, String value)
        {
            var hash = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(value));
            return String.Join("", hash.Select(x => x.ToString("x2")).ToArray());
        }
    }

    public abstract class BasicAuthenticationModuleBase : IHttpModule
    {
        #region IHttpModule メンバ

        public virtual void Dispose()
        {
        }

        public virtual void Init(HttpApplication context)
        {
            context.AuthenticateRequest += Application_OnAuthenticateRequest;
            //context.PreSendRequestHeaders += Application_OnPreSendRequestHeaders;
            context.EndRequest += Application_OnPreSendRequestHeaders;
        }

        #endregion

        protected abstract IPrincipal Authenticate(String userName, String password);
        protected abstract String GetRealm(HttpContextBase ctx);
        protected abstract Boolean IsAuthenticateRequired(HttpContextBase ctx);
        protected abstract Boolean IsSetUser(HttpContextBase ctx);

        private void Application_OnAuthenticateRequest(object sender, EventArgs e)
        {
            HttpContextBase ctx = new HttpContextWrapper((sender as HttpApplication).Context);
            if (IsAuthenticateRequired(ctx))
            {
                try
                {
                    ExecuteAuthenticate(ctx, Authenticate);
                }
                catch (HttpException ex)
                {
                    ctx.Response.StatusCode = ex.GetHttpCode();
                    ctx.Response.StatusDescription = ex.GetHtmlErrorMessage();
                }
            }
        }

        private void Application_OnPreSendRequestHeaders(object sender, EventArgs e)
        {
            HttpContextBase ctx = new HttpContextWrapper((sender as HttpApplication).Context);
            if (IsAuthenticateRequired(ctx))
            {
                AuthorizationFailed(ctx);
            }
        }

        private void ExecuteAuthenticate(HttpContextBase ctx, Func<String, String, IPrincipal> authorizer)
        {
            String authField = ctx.Request.Headers["Authorization"];

            if (String.IsNullOrEmpty(authField))
            {
                throw new HttpException(401, "Authorization Required");
            }

            String[] parts = authField.Split(new char[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
            // ヘッダフィールドの形がおかしいかBasic認証ではない
            if (parts.Length != 2 || String.Compare(parts[0], "Basic", true) != 0)
            {
                throw new HttpException(401, "Authorization Required");
            }

            try
            {
                // Base64 をデコードしてさらに : で区切られてるのを分割する
                String decodedField = Encoding.UTF8.GetString(Convert.FromBase64String(parts[1]));
                parts = decodedField.Split(new char[] { ':' }, 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length != 2)
                {
                    throw new HttpException(401, "Authorization Required");
                }

                // 認証問い合わせ
                IPrincipal principal = authorizer(parts[0], parts[1]);
                if (principal != null)
                {
                    if (IsSetUser(ctx))
                    {
                        ctx.User = principal;
                    }
                }
                else
                {
                    throw new HttpException(401, "Authorization Required");
                }
            }
            catch (FormatException e)
            {
                throw new HttpException(400, "Bad Request");
            }
        }

        private void AuthorizationFailed(HttpContextBase ctx)
        {
            if (ctx.Response.StatusCode == 401)
            {
                ctx.Response.AppendHeader("WWW-Authenticate", String.Format("Basic realm=\"{0}\"", EscapeRealm(GetRealm(ctx))));
            }
        }

        private String EscapeRealm(String realm)
        {
            return realm.Replace(@"\", @"\\").Replace("\"", "\\\"");
        }
    }
}
