using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Security;
using System.Xml.XPath;
using Newtonsoft.Json.Linq;
using MyCompany.Data;
using MyCompany.Handlers;

namespace MyCompany.Services.Rest
{
    public partial class RESTfulResourceBase : RESTfulResourceConfiguration
    {

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _oAuth;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _oAuthMethod;

        private JObject _idClaims;

        public string OAuth
        {
            get
            {
                return _oAuth;
            }
            set
            {
                _oAuth = value;
            }
        }

        public string OAuthMethod
        {
            get
            {
                return _oAuthMethod;
            }
            set
            {
                _oAuthMethod = value;
            }
        }

        public string OAuthMethodName
        {
            get
            {
                var path = string.Format("{0}/{1}", HttpMethod.ToLower(), OAuth);
                if (!string.IsNullOrEmpty(OAuthMethod))
                    path = string.Format("{0}/{1}", path, OAuthMethod);
                return path;
            }
        }

        public string OAuthMethodPath
        {
            get
            {
                return OAuthMethodName.Substring((HttpMethod.Length + 1));
            }
        }

        public override JObject IdClaims
        {
            get
            {
                if (_idClaims == null)
                {
                    _idClaims = new JObject();
                    var authorization = HttpContext.Current.Request.Headers["Authorization"];
                    if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                        ExecuteOAuthPostUserInfo(new JObject(), new JObject(), _idClaims);
                }
                return _idClaims;
            }
        }

        public virtual void ExecuteOAuth(JObject schema, JObject payload, JObject result)
        {
            // create OAuth2 authorization request
            if (OAuthMethodName == "get/auth")
                ExecuteOAuthGetAuth(schema, payload, result);
            // Process the authorization request
            if (OAuthMethodName == "post/auth")
                ExecuteOAuthPostAuth(schema, payload, result);
            // Exchange 'authorization_code' or 'refresh_token' for an access token
            if (OAuthMethodName == "post/token")
                ExecuteOAuthPostToken(schema, payload, result);
            // Exchange 'authorization_code' or 'refresh_token' for an access token
            if (OAuthMethodName == "post/revoke")
                ExecuteOAuthPostRevoke(schema, payload, result);
            // Get the Open ID user claims for a given access token
            if (OAuthMethodName == "post/userinfo")
                ExecuteOAuthPostUserInfo(schema, payload, result);
            // Get the the user info such as photo, etc.
            if (OAuthMethodName.StartsWith("get/userinfo/pictures"))
                ExecuteOAuthGetUserInfoPictures(schema, payload, result);
            // create 'authorization' and 'token' links with parameters
            if (OAuthMethodName.StartsWith("post/auth/"))
                ExecuteOAuthPostAuthClient(schema, payload, result);
            // get the list of client app records
            if (OAuthMethodName == "get/apps")
                ExecuteOAuthGetApps(schema, payload, result);
            // register a client app
            if (OAuthMethodName == "post/apps")
                ExecuteOAuthPostApps(schema, payload, result);
            // get the client app record
            if (OAuthMethodName.StartsWith("get/apps/"))
                ExecuteOAuthGetAppsSingleton(schema, payload, result, null);
            // delete the client app record
            if (OAuthMethodName.StartsWith("delete/apps/"))
                ExecuteOAuthDeleteAppsSingleton(schema, payload, result);
            // patch the client app record
            if (OAuthMethodName.StartsWith("patch/apps/"))
                ExecuteOAuthPatchAppsSingleton(schema, payload, result);
            // get information specified in 'id_token' parameter
            if (OAuthMethodName.StartsWith("get/tokeninfo"))
                ExecuteOAuthGetTokenInfo(schema, payload, result);
        }

        public virtual void ExecuteOAuthGetAuth(JObject schema, JObject payload, JObject result)
        {
            var authRequest = new JObject();
            // verify 'client_id'
            var clientApp = new JObject();
            ExecuteOAuthGetAppsSingleton(schema, payload, clientApp, "invalid_client");
            authRequest["date"] = DateTime.UtcNow.ToString("o");
            authRequest["name"] = clientApp["name"];
            authRequest["author"] = clientApp["author"];
            authRequest["trusted"] = Convert.ToBoolean(clientApp["trusted"]);
            authRequest["code"] = TextUtility.ToUrlEncodedToken(TextUtility.GetUniqueKey(40));
            // verify 'redirect_uri'
            string redirectUri = null;
            try
            {
                redirectUri = new Uri(((string)(payload["redirect_uri"]))).AbsoluteUri;
            }
            catch (Exception ex)
            {
                RESTfulResource.ThrowError("invalid_parameter", "Parameter 'redirect_uri': {0}", ex.Message);
            }
            if ((redirectUri == ((string)(clientApp["redirect_uri"]))) || (redirectUri == ((string)(clientApp["local_redirect_uri"]))))
                authRequest["redirect_uri"] = redirectUri;
            else
                RESTfulResource.ThrowError("invalid_parameter", "Parameter 'redirect_uri' does not match the redirect URIs of '{0}' client application.", clientApp["name"]);
            authRequest["client_id"] = clientApp["client_id"];
            var serverAuthorization = Convert.ToBoolean(clientApp.SelectToken("authorization.server"));
            var nativeAuthorization = Convert.ToBoolean(clientApp.SelectToken("authorization.native"));
            var spaAuthorization = Convert.ToBoolean(clientApp.SelectToken("authorization.spa"));
            if (serverAuthorization)
                authRequest["client_secret"] = TextUtility.ToUrlEncodedToken(((string)(clientApp["client_secret"])));
            var codeChallenge = ((string)(payload["code_challenge"]));
            var codeChallengeMethod = ((string)(payload["code_challenge_method"]));
            if (!(((nativeAuthorization || serverAuthorization) || spaAuthorization)))
                RESTfulResource.ThrowError("unauthorized", "Client application '{0}' is disabled.", clientApp["name"]);
            if (nativeAuthorization || serverAuthorization)
            {
                var codeVerificationRequired = (nativeAuthorization && !((spaAuthorization || serverAuthorization)));
                var clientSecretRequired = (serverAuthorization && !((nativeAuthorization || spaAuthorization)));
                if (string.IsNullOrEmpty(codeChallenge) && (codeVerificationRequired || !string.IsNullOrEmpty(codeChallengeMethod)))
                    RESTfulResource.ThrowError("invalid_argument", "Parameter 'code_challenge' is expected.");
                if (string.IsNullOrEmpty(codeChallengeMethod) && (codeVerificationRequired || !string.IsNullOrEmpty(codeChallenge)))
                    RESTfulResource.ThrowError("invalid_argument", "Parameter 'code_challenge_method' is expected.");
                if (clientSecretRequired)
                    authRequest["client_secret_required"] = true;
                authRequest["code_challenge"] = codeChallenge;
                authRequest["code_challenge_method"] = codeChallengeMethod;
                if (codeVerificationRequired)
                    authRequest["code_verifier_required"] = true;
            }
            else
            {
                if (!string.IsNullOrEmpty(codeChallenge))
                    RESTfulResource.ThrowError("invalid_parameter", "Unexpected parameter 'code_challenge' is specified.");
                if (!string.IsNullOrEmpty(codeChallengeMethod))
                    RESTfulResource.ThrowError("invalid_parameter", "Unexpected parameter 'code_challenge_method' is specified.");
            }
            var scopeList = ScopeListFrom(payload);
            if (scopeList.Count > 0)
            {
                var stdScopes = StandardScopes();
                var appScopes = ApplicationScopes();
                var scopeIndex = 0;
                while (scopeIndex < scopeList.Count)
                {
                    var scope = scopeList[scopeIndex];
                    if (((stdScopes[scope] != null) || (appScopes[scope] != null)) && (scopeList.IndexOf(scope) == scopeIndex))
                        scopeIndex++;
                    else
                        scopeList.RemoveAt(scopeIndex);
                }
                authRequest["scope"] = string.Join(" ", scopeList);
            }
            authRequest["state"] = payload["state"];
            // delete the last request
            var cookie = HttpContext.Current.Request.Cookies[".oauth2"];
            if (cookie != null)
            {
                var lastOAuth2Request = Regex.Match(cookie.Value, "^(.+?)(\\:consent)?$");
                if (lastOAuth2Request.Success)
                    App.AppDataDelete(OAuth2FileName("requests", lastOAuth2Request.Groups[1].Value));
            }
            // create the new request
            var authData = authRequest.ToString();
            var authRef = TextUtility.ToUrlEncodedToken(authData);
            App.AppDataWriteAllText(OAuth2FileName("requests", authRef), authData);
            cookie = new HttpCookie(".oauth2", authRef)
            {
                Expires = DateTime.Now.AddMinutes(AuthorizationRequestLifespan)
            };
            ApplicationServices.SetCookie(cookie);
            HttpContext.Current.Response.Redirect(App.UserHomePageUrl());
        }

        public virtual void ExecuteOAuthPostAuth(JObject schema, JObject payload, JObject result)
        {
            var authRequestFileName = OAuth2FileName("requests", payload["request_id"]);
            var authRequest = ReadOAuth2Data(authRequestFileName, null, "invalid_request", "Invalid OAuth2 authorization 'request_id' is specified.");
            App.AppDataDelete(authRequestFileName);
            // delete '.oauth2' cookie and the request data
            var cookie = HttpContext.Current.Request.Cookies[".oauth2"];
            if (cookie != null)
            {
                cookie.Expires = DateTime.Now.AddDays(-10);
                ApplicationServices.SetCookie(cookie);
                if (!cookie.Value.StartsWith(((string)(payload["request_id"]))))
                    RESTfulResource.ThrowError("invalid_argument", "The 'request_id' does not match the request authorization state.");
            }
            else
                RESTfulResource.ThrowError("invalid_state", "Application is not in the authorization state.");
            if (DateTime.Parse(((string)(authRequest["date"]))).AddMinutes(AuthorizationRequestLifespan) < DateTime.UtcNow)
                RESTfulResource.ThrowError("invalid_argument", "Authorization request has expired.");
            authRequest["date"] = DateTime.UtcNow.AddMinutes(AuthorizationCodeLifespan);
            // save the username to the request
            if (Convert.ToBoolean(ApplicationServicesBase.SettingsProperty("membership.accountManager.enabled", true)) || !HttpContext.Current.User.Identity.IsAuthenticated)
                BearerAuthorizationHeader();
            authRequest["username"] = HttpContext.Current.User.Identity.Name;
            // create a response
            var links = CreateLinks(result);
            var redirectUri = ((string)(authRequest["redirect_uri"]));
            var url = new StringBuilder(redirectUri);
            if (redirectUri.Contains("?") || Regex.IsMatch(redirectUri, "#.+?"))
                url.Append("&");
            else
            {
                if (!redirectUri.Contains("#"))
                    url.Append("?");
            }
            var state = HttpUtility.UrlEncode(Convert.ToString(authRequest["state"]));
            if (((string)(payload["consent"])) == "allow")
            {
                url.AppendFormat("code={0}", authRequest["code"]);
                url.AppendFormat("&state={0}", state);
                authRequest["timezone"] = payload["timezone"];
                authRequest["locale"] = System.Globalization.CultureInfo.CurrentCulture.Name;
                TrimScopesIn(authRequest);
                App.AppDataWriteAllText(OAuth2FileName("codes", authRequest["code"]), authRequest.ToString());
            }
            else
            {
                url.Append("error=access_denied");
                url.AppendFormat("&state={0}", state);
            }
            AddLink("redirect-uri", "GET", links, ("_self:" + url.ToString()));
            OAuthCollectGarbage();
        }

        public virtual void OAuthCollectGarbage()
        {
            // Cleanup is performed when the user approves or denies the authorization request
            var filesToDelete = new List<string>();
            // 1. delete sys/oauth2/requests beyound the lifespan
            filesToDelete.AddRange(App.AppDataSearch("sys/oauth2/requests", "%.json", 3, DateTime.UtcNow.AddMinutes((-1 * AuthorizationRequestLifespan))));
            // 2. delete sys/oauth2/codes beyond the lifespan
            filesToDelete.AddRange(App.AppDataSearch("sys/oauth2/codes", "%.json", 3, DateTime.UtcNow.AddMinutes((-1 * AuthorizationCodeLifespan))));
            // 3. delete sys/oauth2/pictures beyond the lifespan (the duration of the id_token)
            filesToDelete.AddRange(App.AppDataSearch("sys/oauth2/pictures/%", "%.json", 3, DateTime.UtcNow.AddMinutes((-1 * PictureLifespan))));
            // 4. delete sys/oauth2/tokens of this user that have expired
            filesToDelete.AddRange(App.AppDataSearch("sys/oauth2/tokens/%", "%.json", 3, DateTime.UtcNow.AddMinutes((-1 * App.GetAccessTokenDuration("server.rest.authorization.oauth2.accessTokenDuration")))));
            foreach (var filename in filesToDelete)
                App.AppDataDelete(filename);
        }

        public static void EnsureRequiredField(JObject payload, string field, string error, string description)
        {
            var token = payload[field];
            if ((token == null) || (token.Type == JTokenType.Null))
                RESTfulResource.ThrowError(error, description);
        }

        public virtual void ExecuteOAuthPostToken(JObject schema, JObject payload, JObject result)
        {
            var grantType = ((string)(payload["grant_type"]));
            var clientId = Convert.ToString(payload["client_id"]);
            var clientSecret = Convert.ToString(payload["client_secret"]);
            var scopeListAdjusted = ScopeListFrom(payload);
            JObject tokenRequest = null;
            var refreshTokenRotation = false;
            if (grantType == "authorization_code")
            {
                EnsureRequiredField(payload, "code", "invalid_grant", "Field 'code' is expected in the body.");
                var authRequestFileName = OAuth2FileName("codes", payload["code"]);
                tokenRequest = ReadOAuth2Data(authRequestFileName, null, "invalid_grant", "The authorization code is invalid.");
                // validate the request
                if (clientId != Convert.ToString(tokenRequest["client_id"]))
                    RESTfulResource.ThrowError("invalid_client", "Invalid 'client_id' value is specified.");
                if (Convert.ToString(payload["redirect_uri"]) != Convert.ToString(tokenRequest["redirect_uri"]))
                    RESTfulResource.ThrowError("invalid_argument", "Invalid 'request_uri' value is specified.");
                if (Convert.ToBoolean(tokenRequest["client_secret_required"]) && string.IsNullOrEmpty(clientSecret))
                    RESTfulResource.ThrowError("invalid_client", "Field 'client_secret' is required.");
                if (!string.IsNullOrEmpty(clientSecret) && Convert.ToString(tokenRequest["client_secret"]) != TextUtility.ToUrlEncodedToken(clientSecret))
                    RESTfulResource.ThrowError("invalid_client", "Invalid 'client_secret' value is specified.");
                if (scopeListAdjusted.Count > 0)
                    RESTfulResource.ThrowError("invalid_scope", "The scope cannot be changed when exchanging the authorization code for the access token.");
                var codeVerifier = Convert.ToString(payload["code_verifier"]);
                var codeChallenge = Convert.ToString(tokenRequest["code_challenge"]);
                var codeChallengeMethod = Convert.ToString(tokenRequest["code_challenge_method"]);
                if (codeChallengeMethod == "S256")
                    codeVerifier = TextUtility.ToUrlEncodedToken(codeVerifier);
                if (Convert.ToBoolean(tokenRequest["code_verifier_required"]) && string.IsNullOrEmpty(codeVerifier))
                    RESTfulResource.ThrowError("invalid_argument", "Field 'code_verifier' is required.");
                if (!string.IsNullOrEmpty(codeVerifier) && codeVerifier != codeChallenge)
                    RESTfulResource.ThrowError("invalid_argument", "Invalid 'code_verifier' value is specified.");
                App.AppDataDelete(authRequestFileName);
                if (DateTime.Parse(((string)(tokenRequest["date"]))).AddMinutes(AuthorizationCodeLifespan) < DateTime.UtcNow)
                    RESTfulResource.ThrowError("invalid_grant", "The authorization code has expired.");
            }
            if (grantType == "refresh_token")
            {
                EnsureRequiredField(payload, "refresh_token", "invalid_grant", "Field 'refresh_token' is expected in the body.");
                var refreshRequestFileName = OAuth2FileName("tokens/%", payload["refresh_token"]);
                tokenRequest = ReadOAuth2Data(refreshRequestFileName, null, "invalid_grant", "The refresh token is invalid.");
                if (clientId != Convert.ToString(tokenRequest["client_id"]))
                    RESTfulResource.ThrowError("invalid_client", "Invalid 'client_id' value is specified.");
                if (Convert.ToBoolean(tokenRequest["client_secret_required"]) && string.IsNullOrEmpty(clientSecret))
                    RESTfulResource.ThrowError("invalid_client", "Parameter 'client_secret' is required.");
                if (!string.IsNullOrEmpty(clientSecret) && TextUtility.ToUrlEncodedToken(clientSecret) != ((string)(tokenRequest["client_secret"])))
                    RESTfulResource.ThrowError("invalid_client", "Invalid 'client_secret' is specified.");
                // validate the refresh token
                var authTicket = FormsAuthentication.Decrypt(((string)(tokenRequest["token"])));
                if (authTicket.UserData != "REFRESHONLY")
                    RESTfulResource.ThrowError("invalid_grant", "The access token cannot be used to refresh.");
                refreshTokenRotation = Convert.ToBoolean(ApplicationServicesBase.SettingsProperty("server.rest.authorization.oauth2.refreshTokenRotation", true));
                var refreshTokenExpired = !App.ValidateTicket(authTicket);
                // delete the refresh token from the persistent storage
                if (refreshTokenRotation || refreshTokenExpired)
                    App.AppDataDelete(refreshRequestFileName);
                // delete the related access token from the persistent storage
                App.AppDataDelete(OAuth2FileName("tokens/%", tokenRequest["related_token"]));
                // ensure that the token has not expired
                if (refreshTokenExpired)
                    RESTfulResource.ThrowError("invalid_grant", "The refresh token has expired.");
                // adjust the scope list by reducing the number of avaialble scopes to those specified in the payload
                if (scopeListAdjusted.Count > 0)
                {
                    var tokenScopeList = ScopeListFrom(tokenRequest);
                    var newScopeList = new List<string>(tokenScopeList);
                    foreach (var tokenScope in tokenScopeList)
                        if (!scopeListAdjusted.Contains(tokenScope))
                            newScopeList.Remove(tokenScope);
                    tokenRequest["scope"] = string.Join(" ", newScopeList);
                }
            }
            // validate the user
            var user = Membership.GetUser(Convert.ToString(tokenRequest["username"]));
            if (user == null)
                RESTfulResource.ThrowError("invalid_user", "The user account does not exist.");
            if (!user.IsApproved)
                RESTfulResource.ThrowError("invalid_user", "The user account is not approved.");
            if (user.IsLockedOut)
                RESTfulResource.ThrowError("invalid_user", "The user account is locked.");
            // create the response with the access and refresh tokens
            var ticket = App.CreateTicket(user, null, "server.rest.authorization.oauth2.accessTokenDuration", "server.rest.authorization.oauth2.refreshTokenDuration");
            var tokenChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-._~+";
            // do not include "/" in the token
            var accessToken = TextUtility.GetUniqueKey(AccessTokenSize, tokenChars);
            result["access_token"] = accessToken;
            result["expires_in"] = (60 * App.GetAccessTokenDuration("server.rest.authorization.oauth2.accessTokenDuration"));
            result["token_type"] = "Bearer";
            tokenRequest["token"] = ticket.AccessToken;
            tokenRequest["token_type"] = "access";
            tokenRequest.Remove("related_token");
            tokenRequest["token_issued"] = DateTime.UtcNow.ToString("o");
            // create 'id_token'
            var idClaims = EnumerateIdClaims(grantType, user, tokenRequest);
            if ((idClaims != null) && (idClaims.Count > 0))
            {
                result["id_token"] = TextUtility.CreateJwt(idClaims);
                tokenRequest["id_token"] = idClaims;
            }
            // create 'access_token'
            App.AppDataWriteAllText(OAuth2FileName(string.Format("tokens/{0}/access", HttpUtility.UrlEncode(user.UserName)), accessToken), tokenRequest.ToString());
            // create 'refresh_token'
            var refreshTokenDuration = App.GetAccessTokenDuration("server.rest.authorization.oauth2.refreshTokenDuration");
            if ((refreshTokenDuration > 0) && (((grantType == "authorization_code") && (Convert.ToBoolean(tokenRequest["trusted"]) || ScopeListFrom(tokenRequest).Contains("offline_access"))) || refreshTokenRotation))
            {
                var refreshToken = TextUtility.GetUniqueKey(RefreshTokenSize, tokenChars);
                result["refresh_token"] = refreshToken;
                tokenRequest["token"] = ticket.RefreshToken;
                tokenRequest["token_type"] = "refresh";
                tokenRequest["related_token"] = accessToken;
                tokenRequest.Remove("id_token");
                App.AppDataWriteAllText(OAuth2FileName(string.Format("tokens/{0}/refresh", HttpUtility.UrlEncode(user.UserName)), refreshToken), tokenRequest.ToString());
            }
            var scope = Convert.ToString(tokenRequest["scope"]);
            if (!string.IsNullOrEmpty(scope))
                result["scope"] = scope;
        }

        public virtual void ExecuteOAuthPostRevoke(JObject schema, JObject payload, JObject result)
        {
            var clientId = Convert.ToString(payload["client_id"]);
            var clientSecret = Convert.ToString(payload["client_secret"]);
            var tokenRequest = ReadOAuth2Data(OAuth2FileName("%", payload["token"]), null, "invalid_grant", "Invalid or expired token is specified.");
            // validate the request
            if (clientId != Convert.ToString(tokenRequest["client_id"]))
                RESTfulResource.ThrowError("invalid_client", "Invalid 'client_id' value is specified.");
            if (Convert.ToBoolean(tokenRequest["client_secret_required"]) && string.IsNullOrEmpty(clientSecret))
                RESTfulResource.ThrowError("invalid_client", "Field 'client_secret' is required.");
            if (!string.IsNullOrEmpty(clientSecret) && Convert.ToString(tokenRequest["client_secret"]) != TextUtility.ToUrlEncodedToken(clientSecret))
                RESTfulResource.ThrowError("invalid_client", "Invalid 'client_secret' value is specified.");
            // delete the token and the related token if any
            App.AppDataDelete(OAuth2FileName("%", payload["token"]));
            var relatedToken = ((string)(tokenRequest["related_token"]));
            if (relatedToken != null)
                App.AppDataDelete(OAuth2FileName("%", relatedToken));
        }

        public string BearerAuthorizationHeader()
        {
            var authorization = HttpContext.Current.Request.Headers["Authorization"];
            if (string.IsNullOrEmpty(authorization) || !authorization.StartsWith("Bearer "))
                RESTfulResource.ThrowError(403, "unauthorized", "Specify an access token in the Bearer 'Authorization' header.");
            return authorization.Substring("Bearer ".Length);
        }

        public virtual void ExecuteOAuthGetUserInfoPictures(JObject schema, JObject payload, JObject result)
        {
            var type = ((string)(payload["type"]));
            var filename = ((string)(payload["filename"]));
            MembershipUser user = null;
            if (string.IsNullOrEmpty(filename))
            {
                var authorization = BearerAuthorizationHeader();
                var accessToken = ReadOAuth2Data("tokens/%", authorization, "invalid_token", "Invalid or expired access token.");
                user = Membership.GetUser();
            }
            else
            {
                var picture = ReadOAuth2Data("pictures/%", Path.GetFileNameWithoutExtension(filename), "invalid_path", string.Format("User picture {0} '{1}' does not exist.", type, filename));
                user = Membership.GetUser(((string)(picture["username"])));
                if (user == null)
                    RESTfulResource.ThrowError(404, "invalid_path", "The user does not exist.");
            }
            byte[] imageData = null;
            string imageContentType = null;
            if (!TryGetUserImage(user, type, out imageData, out imageContentType))
                RESTfulResource.ThrowError(404, "invalid_path", "User photo does not exist.");
            var response = HttpContext.Current.Response;
            response.ContentType = imageContentType;
            response.Headers.Remove("Set-Cookie");
            response.Cache.SetMaxAge(TimeSpan.FromMinutes(PictureLifespan));
            response.OutputStream.Write(imageData, 0, imageData.Length);
            response.End();
        }

        public static bool TryGetUserImage(MembershipUser user, string type, out byte[] data, out string contentType)
        {
            data = null;
            contentType = null;
            var app = ApplicationServicesBase.Current;
            var url = app.UserPictureUrl(user);
            if (!string.IsNullOrEmpty(url))
            {
                var request = WebRequest.Create(url);
                using (var imageResponse = request.GetResponse())
                {
                    using (var stream = imageResponse.GetResponseStream())
                    {
                        using (var ms = new MemoryStream())
                        {
                            contentType = imageResponse.ContentType;
                            data = ms.ToArray();
                        }
                    }
                }
            }
            else
            {
                url = app.UserPictureFilePath(user);
                if (!string.IsNullOrEmpty(url))
                {
                    data = File.ReadAllBytes(url);
                    contentType = ("image/" + Path.GetExtension(url).Substring(1));
                }
            }
            if ((data == null) && ApplicationServicesBase.IsSiteContentEnabled)
            {
                var list = app.ReadSiteContent("sys/users", (user.UserName + ".%"));
                foreach (var file in list)
                    if (file.ContentType.StartsWith("image/") && (file.Data != null))
                    {
                        data = file.Data;
                        contentType = file.ContentType;
                        break;
                    }
            }
            if (data == null)
                return false;
            if (type == "thumbnail")
            {
                var img = ((Image)(new ImageConverter().ConvertFrom(data)));
                var thumbnailSize = 96;
                if ((img.Width > thumbnailSize) || (img.Height > thumbnailSize))
                {
                    var scale = (((float)(img.Width)) / thumbnailSize);
                    var height = ((int)((img.Height / scale)));
                    var width = thumbnailSize;
                    if (img.Height < img.Width)
                    {
                        scale = (((float)(img.Height)) / thumbnailSize);
                        height = thumbnailSize;
                        width = ((int)((img.Width / scale)));
                    }
                    var originalImg = img;
                    if (height > width)
                    {
                        width = ((int)((((float)(width)) * (((float)(thumbnailSize)) / ((float)(height))))));
                        height = thumbnailSize;
                    }
                    img = Blob.ResizeImage(img, width, height);
                    originalImg.Dispose();
                }
                using (var output = new MemoryStream())
                {
                    var encoderParams = new System.Drawing.Imaging.EncoderParameters(1);
                    encoderParams.Param[0] = new System.Drawing.Imaging.EncoderParameter(System.Drawing.Imaging.Encoder.Quality, Convert.ToInt64(85));
                    img.Save(output, Blob.ImageFormatToEncoder(System.Drawing.Imaging.ImageFormat.Jpeg), encoderParams);
                    data = output.ToArray();
                    contentType = "image/jpeg";
                }
                img.Dispose();
            }
            return true;
        }

        public virtual void ExecuteOAuthPostUserInfo(JObject schema, JObject payload, JObject result)
        {
            var authorization = BearerAuthorizationHeader();
            var accessToken = ReadOAuth2Data("tokens/%", authorization, "invalid_token", "Invalid or expired access token.");
            var claims = EnumerateIdClaims("authorization_code", Membership.GetUser(), accessToken);
            if ((claims != null) && (Convert.ToBoolean(accessToken["trusted"]) || ScopeListFrom(accessToken).Contains("offline_access")))
                foreach (var p in claims.Properties())
                    if (!Regex.IsMatch(p.Name, "^(aud|azp|exp|iat|iss)$"))
                        result.Add(p);
        }

        public virtual void ExecuteOAuthGetTokenInfo(JObject schema, JObject payload, JObject result)
        {
            var idToken = ((string)(payload["id_token"]));
            if (TextUtility.ValidateJwt(idToken))
            {
                var claims = TextUtility.ParseYamlOrJson(Encoding.UTF8.GetString(TextUtility.FromBase64UrlEncoded(idToken.Split('.')[1])));
                var exp = claims["exp"];
                if (exp != null)
                    claims.AddFirst(new JProperty("active", (DateTimeOffset.UtcNow.ToUnixTimeSeconds() < Convert.ToInt64(exp))));
                foreach (var p in claims.Properties())
                    result.Add(p);
                var jose = TextUtility.ParseYamlOrJson(Encoding.UTF8.GetString(TextUtility.FromBase64UrlEncoded(idToken.Split('.')[0])));
                result["alg"] = jose["alg"];
            }
            else
                RESTfulResource.ThrowError("invalid_token", "The token specified in 'id_token' parameter is invalid.");
        }

        protected virtual JObject ReadOAuth2Data(string path, object id, string error, string errorDescription)
        {
            if (id != null)
                path = OAuth2FileName(path, id);
            var data = App.AppDataReadAllText(path);
            if (data == null)
                RESTfulResource.ThrowError(error, errorDescription);
            return TextUtility.ParseYamlOrJson(data);
        }

        public virtual List<string> ScopeListFrom(JObject context)
        {
            var scope = Convert.ToString(context["scope"]);
            return new List<string>(scope.Split(new char[] {
                            ' ',
                            ','}, StringSplitOptions.RemoveEmptyEntries));
        }

        public virtual bool TrimScopesIn(JObject context)
        {
            var changed = false;
            var scopeList = ScopeListFrom(context);
            var user = HttpContext.Current.User;
            if (user.Identity.IsAuthenticated)
            {
                var appScopes = ApplicationScopes();
                var stdScopes = StandardScopes();
                var i = 0;
                while (i < scopeList.Count)
                {
                    var scope = scopeList[i];
                    var scopeDef = appScopes[scope];
                    if (scopeDef != null)
                    {
                        var roles = Convert.ToString(scopeDef["role"]).Split(new char[] {
                                    ' ',
                                    ','}, StringSplitOptions.RemoveEmptyEntries);
                        if (roles.Length > 0)
                        {
                            if (DataControllerBase.UserIsInRole(roles))
                                i++;
                            else
                            {
                                changed = true;
                                scopeList.RemoveAt(i);
                            }
                        }
                        else
                            i++;
                    }
                    else
                    {
                        if (stdScopes[scope] == null)
                        {
                            changed = true;
                            scopeList.RemoveAt(i);
                        }
                        else
                            i++;
                    }
                }
            }
            if (changed)
                context["scope"] = string.Join(" ", scopeList);
            return changed;
        }

        public virtual JObject EnumerateIdClaims(string grantType, MembershipUser user, JObject context)
        {
            if ((IdTokenDuration > 0) && ((grantType == "authorization_code") || ((grantType == "refresh_token") && Convert.ToBoolean(ApplicationServices.SettingsProperty("server.rest.authorization.oauth2.idTokenRefresh", true)))))
            {
                var scopeList = ScopeListFrom(context);
                var clientId = Convert.ToString(context["client_id"]);
                var claims = new JObject();
                // "openid" scope
                if (scopeList.Contains("openid"))
                {
                    claims["iss"] = ApplicationServicesBase.ResolveClientUrl("~/oauth2/v2");
                    claims["azp"] = clientId;
                    claims["aud"] = ApplicationServicesBase.ResolveClientUrl("~/v2");
                    claims["sub"] = JToken.FromObject(user.ProviderUserKey);
                    claims["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    claims["exp"] = DateTimeOffset.UtcNow.AddMinutes(IdTokenDuration).ToUnixTimeSeconds();
                }
                else
                    return null;
                if (scopeList.Contains("email"))
                {
                    claims["email"] = user.Email;
                    claims["email_verified"] = true;
                }
                // "profile" scope
                if (scopeList.Contains("profile"))
                {
                    claims["name"] = null;
                    claims["given_name"] = null;
                    claims["family_name"] = null;
                    claims["middle_name"] = null;
                    claims["nickname"] = null;
                    claims["preferred_username"] = null;
                    claims["profile"] = null;
                    claims["picture"] = ToPictureClaim(user);
                    if (OAuth == "userinfo")
                    {
                        var picture = ((string)(claims["picture"]));
                        if (!string.IsNullOrEmpty(picture))
                            claims["picture_thumbnail"] = ApplicationServicesBase.ResolveClientUrl(string.Format("~/oauth2/v2/userinfo/pictures/thumbnail/{0}.jpeg", Path.GetFileNameWithoutExtension(picture)));
                    }
                    claims["gender"] = null;
                    claims["birthdate"] = null;
                    claims["zoneinfo"] = context["timezone"];
                    claims["locale"] = context["locale"];
                    claims["updated_at"] = null;
                }
                // "address" scope
                if (scopeList.Contains("address"))
                {
                    var address = new JObject();
                    claims["address"] = address;
                    address["formatted"] = null;
                    address["street_address"] = null;
                    address["locality"] = null;
                    address["region"] = null;
                    address["postal_code"] = null;
                    address["country"] = null;
                }
                // "phone" scope
                if (scopeList.Contains("phone"))
                {
                    claims["phone_number"] = null;
                    claims["phone_number_verified"] = false;
                }
                if (scopeList.Count > 0)
                    claims["scope"] = context["scope"];
                App.EnumerateIdClaims(user, claims, scopeList);
                return claims;
            }
            return null;
        }

        public string ToPictureClaim(MembershipUser user)
        {
            try
            {
                var pictureData = App.AppDataReadAllText(string.Format("sys/oauth2/pictures/{0}/%.json", HttpUtility.UrlEncode(user.UserName)));
                JObject picture = null;
                if (pictureData != null)
                    picture = TextUtility.ParseYamlOrJson(pictureData);
                if ((picture != null) && (DateTime.Parse(((string)(picture["date"]))).AddMinutes(PictureLifespan) < DateTime.UtcNow))
                {
                    App.AppDataDelete(string.Format("sys/oauth2/pictures/%/{0}.json", picture["id"]));
                    pictureData = null;
                }
                if (pictureData == null)
                {
                    byte[] imageData = null;
                    string imageContentType = null;
                    if (TryGetUserImage(user, "original", out imageData, out imageContentType))
                    {
                        picture = new JObject();
                        picture["username"] = user.UserName;
                        picture["id"] = TextUtility.ToUrlEncodedToken(Guid.NewGuid().ToString());
                        picture["date"] = DateTime.UtcNow.ToString("o");
                        picture["contentType"] = imageContentType;
                        picture["extension"] = ((string)(picture["contentType"])).Split('/')[1];
                        pictureData = picture.ToString();
                        App.AppDataWriteAllText(string.Format("sys/oauth2/pictures/{0}/{1}.json", HttpUtility.UrlEncode(user.UserName), picture["id"]), pictureData);
                    }
                }
                if (picture != null)
                    return ApplicationServicesBase.ResolveClientUrl(string.Format("~/oauth2/v2/userinfo/pictures/original/{0}.{1}", picture["id"], picture["extension"]));
                else
                    return null;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        public virtual void ExecuteOAuthPostAuthClient(JObject schema, JObject payload, JObject result)
        {
            var appReg = new JObject();
            ExecuteOAuthGetAppsSingleton(schema, payload, appReg, "invalid_client");
            var links = CreateLinks(result, true);
            var inputSchema = ((JObject)(schema["_input"]));
            // produce the "mobile" authorization response
            var authorizeLinkInfo = Regex.Match(OAuthMethodName, "post/auth/(pkce|spa|server)");
            if (authorizeLinkInfo.Success)
            {
                var isPKCE = (authorizeLinkInfo.Groups[1].Value == "pkce");
                var isServer = (authorizeLinkInfo.Groups[1].Value == "server");
                if (isServer)
                    isPKCE = true;
                var state = ((string)(GetPropertyValue(payload, "state", inputSchema)));
                if (string.IsNullOrEmpty(state))
                    state = TextUtility.GetUniqueKey(16);
                result["state"] = state;
                string codeChallenge = null;
                string codeChallengeMethod = null;
                string codeVerifier = null;
                if (isPKCE)
                {
                    codeChallenge = ((string)(GetPropertyValue(payload, "code_challenge", inputSchema)));
                    codeChallengeMethod = ((string)(GetPropertyValue(payload, "code_challenge_method", inputSchema)));
                    if (string.IsNullOrEmpty(codeChallengeMethod))
                        codeChallengeMethod = "S256";
                    if (string.IsNullOrEmpty(codeChallenge))
                        codeChallenge = TextUtility.GetUniqueKey(64, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-._~");
                    codeVerifier = codeChallenge;
                    if (codeChallengeMethod == "S256")
                        codeChallenge = TextUtility.ToUrlEncodedToken(codeChallenge);
                }
                var token = new JObject();
                AddLink("selfLink", "POST", CreateLinks(token), "{0}/oauth2/v2/token", ApplicationServices.ResolveClientUrl("~/"));
                result.Add(new JProperty("token", token));
                token["grant_type"] = "authorization_code";
                token["code"] = null;
                var redirectUri = Convert.ToString(payload["redirect_uri"]);
                if (redirectUri != Convert.ToString(appReg["redirect_uri"]) && redirectUri != Convert.ToString(appReg["local_redirect_uri"]))
                    RESTfulResource.ThrowError("invalid_argument", "The 'redirect_uri' value does not match the URIs of the client application registration.");
                token["redirect_uri"] = redirectUri;
                token["client_id"] = payload["client_id"];
                if (isServer)
                {
                    var clientSecret = Convert.ToString(payload["client_secret"]);
                    if (clientSecret != Convert.ToString(appReg["client_secret"]))
                        RESTfulResource.ThrowError("invalid_client", "The 'client_secret' value does not match the client application registration.");
                    token["client_secret"] = clientSecret;
                }
                if (isPKCE)
                    token["code_verifier"] = codeVerifier;
                var url = new StringBuilder();
                var clientIdParam = GetPropertyValue(payload, "client_id", inputSchema);
                var redirectUriParam = HttpUtility.UrlEncode(((string)(GetPropertyValue(payload, "redirect_uri", inputSchema))));
                var scopeParam = HttpUtility.UrlEncode(((string)(GetPropertyValue(payload, "scope", inputSchema))));
                url.AppendFormat("{0}/oauth2/v2/auth?response_type=code&client_id={1}&redirect_uri={2}&scope={3}&state={4}", ApplicationServices.ResolveClientUrl("~/"), clientIdParam, redirectUriParam, scopeParam, HttpUtility.UrlEncode(state));
                if (isPKCE)
                    url.AppendFormat("&code_challenge={0}&code_challenge_method={1}", HttpUtility.UrlEncode(codeChallenge), codeChallengeMethod);
                AddLink("authorize", "GET", links, url.ToString());
            }
        }

        public virtual void ExecuteOAuthAppsValidate(JObject result)
        {
            var url = Convert.ToString(result["redirect_uri"]);
            if (!string.IsNullOrEmpty(url))
                try
                {
                    result["redirect_uri"] = new Uri(url).AbsoluteUri;
                }
                catch (Exception ex)
                {
                    RESTfulResource.ThrowError("invalid_argument", ("Invalid 'redirect_uri' value. " + ex.Message));
                }
            url = Convert.ToString(result["local_redirect_uri"]);
            if (!string.IsNullOrEmpty(url))
                try
                {
                    var redirectUri = new Uri(url);
                    if (!Regex.IsMatch(redirectUri.Scheme, "^https?$"))
                        throw new Exception("Only 'http' and 'https' protocols are allowed.");
                    if (redirectUri.Host != "localhost")
                        throw new Exception(string.Format("Host '{0}' is not allowed. Use 'localhost' instead.", redirectUri.Host));
                    result["local_redirect_uri"] = redirectUri.AbsoluteUri;
                }
                catch (Exception ex)
                {
                    RESTfulResource.ThrowError("invalid_argument", ("Invalid 'local_redirect_uri' value. " + ex.Message));
                }
            if (Convert.ToBoolean(result.SelectToken("authorization.server")) && string.IsNullOrEmpty(((string)(result["client_secret"]))))
                result["client_secret"] = TextUtility.GetUniqueKey(64, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-._~");
        }

        protected virtual string ExecuteOAuthAppsLinks(JObject result)
        {
            var clientId = ((string)(result["client_id"]));
            var resourceLocation = ("~/oauth2/v2/apps/" + clientId);
            var links = CreateLinks(result, true);
            AddLink("selfLink", "GET", links, resourceLocation);
            AddLink("editLink", "PATCH", links, resourceLocation);
            AddLink("deleteLink", "DELETE", links, resourceLocation);
            return resourceLocation;
        }

        public virtual void ExecuteOAuthPostApps(JObject schema, JObject payload, JObject result)
        {
            var clientId = TextUtility.GetUniqueKey(43);
            result["name"] = payload["name"];
            result["author"] = payload["author"];
            result["client_id"] = clientId;
            if (payload["client_secret"] != null)
                result["client_secret"] = payload["client_secret"];
            result["redirect_uri"] = payload["redirect_uri"];
            if (payload["local_redirect_uri"] != null)
                result["local_redirect_uri"] = payload["local_redirect_uri"];
            var authorization = payload["authorization"];
            if (authorization == null)
                RESTfulResource.ThrowError(404, "invalid_parameter", "Field 'authorization' is required.");
            result["authorization"] = authorization;
            result["trusted"] = payload["trusted"];
            ExecuteOAuthAppsValidate(result);
            App.AppDataWriteAllText(OAuth2FileName("apps", clientId), result.ToString());
            ExecuteOAuthAppsUpdateCORs(result, new JObject());
            HttpContext.Current.Response.StatusCode = 201;
            HttpContext.Current.Response.Headers["Location"] = ToServiceUrl(ExecuteOAuthAppsLinks(result));
        }

        public virtual void ExecuteOAuthGetApps(JObject schema, JObject payload, JObject result)
        {
            var regList = App.AppDataSearch("sys/oauth2/apps", "%.json");
            var collection = new JArray();
            result["count"] = regList.Length;
            result[CollectionKey] = collection;
            var sortedApps = new SortedDictionary<string, JObject>();
            foreach (var filename in regList)
            {
                var appReg = TextUtility.ParseYamlOrJson(App.AppDataReadAllText(filename));
                var item = new JObject();
                foreach (var p in appReg.Properties())
                    if ((p.Name == "client_secret") && p.Value.Type != JTokenType.Null)
                    {
                        var secret = Convert.ToString(p.Value);
                        if (secret.Length > 6)
                            secret = secret.Substring((secret.Length - 6)).PadLeft((secret.Length - 6), '*');
                        item.Add(p.Name, secret);
                    }
                    else
                        item.Add(p);
                var itemLinks = CreateLinks(item);
                if (itemLinks != null)
                    AddLink("selfLink", "GET", itemLinks, "~/oauth2/v2/apps/{0}", appReg["client_id"]);
                var appName = ((string)(item["name"]));
                if (sortedApps.ContainsKey(appName))
                    appName = ((string)(item["client_id"]));
                sortedApps[appName] = item;
            }
            foreach (var name in sortedApps.Keys)
                collection.Add(sortedApps[name]);
            // add links
            var links = CreateLinks(result);
            if (links != null)
            {
                AddLink("selfLink", "GET", links, "~/oauth2/v2/apps");
                AddLink("createLink", "POST", links, "~/oauth2/v2/apps");
            }
        }

        public virtual void ExecuteOAuthGetAppsSingleton(JObject schema, JObject payload, JObject result, string error)
        {
            if (string.IsNullOrEmpty(error))
                error = "invalid_path";
            var appReg = App.AppDataReadAllText(OAuth2FileName("apps", payload["client_id"]));
            if (appReg == null)
                RESTfulResource.ThrowError(404, error, "Client application '{0}' is not registered.", payload["client_id"]);
            foreach (var p in TextUtility.ParseYamlOrJson(appReg).Properties())
                result.Add(p);
            if (IsImmutable)
                ExecuteOAuthAppsLinks(result);
        }

        public virtual void ExecuteOAuthDeleteAppsSingleton(JObject schema, JObject payload, JObject result)
        {
            ExecuteOAuthGetAppsSingleton(schema, payload, result, null);
            App.AppDataDelete(OAuth2FileName("apps", payload["client_id"]));
            ExecuteOAuthAppsUpdateCORs(result, result);
            result.RemoveAll();
        }

        public virtual void ExecuteOAuthPatchAppsSingleton(JObject schema, JObject payload, JObject result)
        {
            ExecuteOAuthGetAppsSingleton(schema, payload, result, null);
            var original = result.DeepClone();
            if (payload["name"] != null)
                result["name"] = payload["name"];
            if (payload["author"] != null)
                result["author"] = payload["author"];
            if (payload["client_secret"] != null)
                result["client_secret"] = payload["client_secret"];
            if (payload["redirect_uri"] != null)
                result["redirect_uri"] = payload["redirect_uri"];
            if (payload["local_redirect_uri"] != null)
                result["local_redirect_uri"] = payload["local_redirect_uri"];
            if (payload["authorization"] != null)
            {
                if (result["authorization"] == null)
                    result["authorization"] = payload["authorization"];
                else
                    foreach (var p in ((JObject)(payload["authorization"])).Properties())
                        result["authorization"][p.Name] = p.Value;
            }
            if (payload["trusted"] != null)
                result["trusted"] = payload["trusted"];
            ExecuteOAuthAppsValidate(result);
            App.AppDataWriteAllText(OAuth2FileName("apps", result["client_id"]), result.ToString());
            ExecuteOAuthAppsLinks(result);
            ExecuteOAuthAppsUpdateCORs(result, ((JObject)(original)));
        }

        public virtual void ExecuteOAuthAppsUpdateCORs(JObject appReg, JObject appRegOriginal)
        {
            foreach (var propName in new string[] {
                    "redirect_uri",
                    "local_redirect_uri"})
            {
                var redirectUri = ((string)(appReg[propName]));
                var originalRedirectUri = ((string)(appRegOriginal[propName]));
                // delete the previous CORs entries
                if (!string.IsNullOrEmpty(originalRedirectUri))
                {
                    App.AppDataDelete(string.Format("sys/cors/{0}/{1}.json", TextUtility.ToUrlEncodedToken(UriToCORsOrigin(originalRedirectUri)), appReg["client_id"]));
                    HttpContext.Current.Cache.Remove(("cors_origin_" + UriToCORsOrigin(originalRedirectUri)));
                }
                // create the new CORs entries
                if ((!string.IsNullOrEmpty(redirectUri) && HttpMethod != "DELETE") && (Convert.ToBoolean(appReg.SelectToken("authorization.spa")) || Convert.ToBoolean(appReg.SelectToken("authorization.native"))))
                {
                    var data = new JObject();
                    data["app"] = appReg["name"];
                    data["client_id"] = appReg["client_id"];
                    data["uri"] = redirectUri;
                    data["type"] = propName;
                    data["origin"] = UriToCORsOrigin(redirectUri);
                    App.AppDataWriteAllText(string.Format("sys/cors/{0}/{1}.json", TextUtility.ToUrlEncodedToken(((string)(data["origin"]))), appReg["client_id"]), data.ToString());
                }
            }
        }

        public static string UriToCORsOrigin(string appUri)
        {
            var url = new Uri(appUri);
            var origin = string.Format("{0}://{1}", url.Scheme, url.Host);
            if (url.Port != 80)
                origin = string.Format("{0}:{1}", origin, url.Port);
            return origin;
        }
    }
}
