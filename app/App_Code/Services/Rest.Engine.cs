using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Caching;
using System.Web.Security;
using System.Xml.XPath;
using Newtonsoft.Json.Linq;
using MyCompany.Data;
using MyCompany.Handlers;
using MyCompany.Web;

namespace MyCompany.Services.Rest
{
    public partial class RESTfulResource : RESTfulResourceBase
    {

        public static Regex ApiRegex = new Regex("~(\\/oauth2)?\\/v2(\\/|$)");

        public static Regex BasicAuthSupportedRegex = new Regex("~\\/oauth2\\/v2\\/(token|revoke)$");

        public static Regex AnonymousAccessSupportedRegex = new Regex("~\\/v2($|\\/js\\/)");

        static RESTfulResource()
        {
            OperationTypes["Number"] = new string[] {
                    "=",
                    "<>",
                    "<",
                    ">",
                    "<=",
                    ">=",
                    "$between",
                    "$in",
                    "$notin",
                    "$isnotempty",
                    "$isempty"};
            OperationTypes["Text"] = new string[] {
                    "=",
                    "<>",
                    "$beginswith",
                    "$doesnotbeginwith",
                    "$contains",
                    "$doesnotcontain",
                    "$endswith",
                    "$doesnotendwith",
                    "$in",
                    "$notin",
                    "$isnotempty",
                    "$isempty"};
            OperationTypes["Logical"] = new string[] {
                    "$true",
                    "$false",
                    "$isnotempty",
                    "$isempty"};
            OperationTypes["Date"] = new string[] {
                    "=",
                    "<>",
                    "<",
                    ">",
                    "<=",
                    ">=",
                    "$between",
                    "$in",
                    "$notin",
                    "$isnotempty",
                    "$isempty",
                    "$tomorrow",
                    "$today",
                    "$yesterday",
                    "$nextweek",
                    "$thisweek",
                    "$lastweek",
                    "$nextmonth",
                    "$thismonth",
                    "$lastmonth",
                    "$nextquarter",
                    "$thisquarter",
                    "$lastquarter",
                    "$thisyear",
                    "$nextyear",
                    "$lastyear",
                    "$yeartodate",
                    "$past",
                    "$future",
                    "$quarter1",
                    "$quarter2",
                    "$quarter3",
                    "$quarter4",
                    "$month1",
                    "$month2",
                    "$month3",
                    "$month4",
                    "$month5",
                    "$month6",
                    "$month7",
                    "$month8",
                    "$month9",
                    "$month10",
                    "$month11",
                    "$month12"};
            // =
            var c = new OpConstraint()
            {
                Name = "equals,=",
                Op = "=",
                MinValCount = 1,
                MaxValCount = 1,
                ArrayOp = "includes"
            };
            // <>
            c = new OpConstraint()
            {
                Name = "doesNotEqual,<>,!=",
                Op = "<>",
                MinValCount = 1,
                MaxValCount = 1,
                ArrayOp = "doesNotInclude"
            };
            // >
            c = new OpConstraint()
            {
                Name = "greaterThan,>",
                Op = ">",
                MinValCount = 1,
                MaxValCount = 1
            };
            // >=
            c = new OpConstraint()
            {
                Name = "greaterThanOrEqual,>=",
                Op = ">=",
                MinValCount = 1,
                MaxValCount = 1
            };
            // $between
            c = new OpConstraint()
            {
                Name = "between",
                Op = "$between",
                MinValCount = 2,
                MaxValCount = 2,
                Join = "$and$",
                UrlArrays = true
            };
            // $in
            c = new OpConstraint()
            {
                Name = "includes",
                Op = "$in",
                MinValCount = 1,
                MaxValCount = int.MaxValue,
                Join = "$or$",
                UrlArrays = true
            };
            // $notin
            c = new OpConstraint()
            {
                Name = "doesNotInclude",
                Op = "$notin",
                MinValCount = 1,
                MaxValCount = int.MaxValue,
                Join = "$or$",
                UrlArrays = true
            };
            // $isempty
            c = new OpConstraint()
            {
                Name = "empty,isEmtpy,isNull",
                Op = "$isempty",
                NegativeOp = "notEmpty"
            };
            // $isnotempty
            c = new OpConstraint()
            {
                Name = "notEmpty,isNotEmpty,isNotNull",
                Op = "$isnotempty",
                NegativeOp = "empty"
            };
            // <
            c = new OpConstraint()
            {
                Name = "lessThan,<",
                Op = ">",
                MinValCount = 1,
                MaxValCount = 1
            };
            // <=
            c = new OpConstraint()
            {
                Name = "lessThanOrEqual,<=",
                Op = "<=",
                MinValCount = 1,
                MaxValCount = 1
            };
        }

        public RESTfulResource()
        {
            HttpContext.Current.Items["RESTfulResource_Current"] = this;
        }

        public static RESTfulResource Current
        {
            get
            {
                return ((RESTfulResource)(HttpContext.Current.Items["RESTfulResource_Current"]));
            }
        }

        public static bool IsRequested
        {
            get
            {
                return ApiRegex.IsMatch(HttpContext.Current.Request.AppRelativeCurrentExecutionFilePath);
            }
        }

        public static bool BasicAuthSupported
        {
            get
            {
                return BasicAuthSupportedRegex.IsMatch(HttpContext.Current.Request.AppRelativeCurrentExecutionFilePath);
            }
        }

        public static bool IsOAuth
        {
            get
            {
                var m = ApiRegex.Match(HttpContext.Current.Request.AppRelativeCurrentExecutionFilePath);
                return (m.Success && (m.Groups[1].Value.Length > 0));
            }
        }

        public static bool AnonymousAccessSupported
        {
            get
            {
                return AnonymousAccessSupportedRegex.IsMatch(HttpContext.Current.Request.AppRelativeCurrentExecutionFilePath);
            }
        }

        public static string PublicApiKey
        {
            get
            {
                return ((string)(HttpContext.Current.Items["x-api-key"]));
            }
            set
            {
                HttpContext.Current.Items["x-api-key"] = value;
            }
        }

        public static string PublicApiKeyInPath
        {
            get
            {
                return ((string)(HttpContext.Current.Items["x-api-key-in-path"]));
            }
            set
            {
                HttpContext.Current.Items["x-api-key-in-path"] = value;
            }
        }

        public static List<string> Scopes
        {
            get
            {
                var scope = Convert.ToString(HttpContext.Current.Items["OAuth2_scope"]);
                return new List<string>(scope.Split(new char[] {
                                ' ',
                                ','}, StringSplitOptions.RemoveEmptyEntries));
            }
            set
            {
                HttpContext.Current.Items["OAuth2_scope"] = value;
            }
        }

        public static JObject IdToken
        {
            get
            {
                var token = ((JObject)(HttpContext.Current.Items["RESTfulResource_IdToken"]));
                if (token == null)
                {
                    token = new JObject();
                    IdToken = token;
                }
                return token;
            }
            set
            {
                HttpContext.Current.Items["RESTfulResource_IdToken"] = value;
            }
        }

        public static string LatestVersion
        {
            get
            {
                return ((string)(HttpContext.Current.Items["RESTfulResource_LatestVersion"]));
            }
            set
            {
                HttpContext.Current.Items["RESTfulResource_LatestVersion"] = value;
            }
        }

        public static bool IsAuthorized(string action, string schemaDef)
        {
            return IsAuthorized(((JObject)(TextUtility.ParseYamlOrJson(schemaDef, true)[action])));
        }

        public static bool IsAuthorized(JObject actionSchema)
        {
            if (actionSchema != null)
            {
                var roles = Convert.ToString(actionSchema["_roles"]);
                return (string.IsNullOrEmpty(roles) || DataControllerBase.UserIsInRole(roles));
            }
            return true;
        }

        public static string[] AuthorizationToLogin(string authorization)
        {
            if (string.IsNullOrEmpty(authorization))
                authorization = HttpContext.Current.Request.Headers["Authorization"];
            if ((authorization != null) && authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                var login = Encoding.UTF8.GetString(Convert.FromBase64String(authorization.Substring(6))).Split(new char[] {
                            ':'}, 2);
                if (login.Length == 1)
                    return new string[] {
                            login[0],
                            login[0]};
                else
                {
                    if (login.Length == 2)
                        return login;
                }
            }
            return null;
        }

        public static void ThrowError(string error, string description, params object[] args)
        {
            ThrowError(-1, error, description, args);
        }

        public static void ThrowError(int httpCode, string error, string description, params object[] args)
        {
            if (args.Length > 0)
                description = string.Format(description, args);
            throw new RESTfulResourceException(httpCode, error, description);
        }

        public static void ThrowError(int httpCode, bool schemaHint, string error, string description, params object[] args)
        {
            if (args.Length > 0)
                description = string.Format(description, args);
            throw new RESTfulResourceException(httpCode, schemaHint, error, description);
        }

        public static string LoadContent()
        {
            string result = null;
            var context = HttpContext.Current;
            var oauthCookie = context.Request.Cookies[".oauth2"];
            if (oauthCookie != null)
            {
                var oauth2Request = Regex.Match(oauthCookie.Value, "^(.+?)(\\:consent)?$");
                if (oauth2Request.Success)
                {
                    var requestId = oauth2Request.Groups[1].Value;
                    var authData = ApplicationServicesBase.Current.AppDataReadAllText(OAuth2FileName("requests", requestId));
                    if (authData != null)
                    {
                        var authRequest = TextUtility.ParseYamlOrJson(authData);
                        var appState = new JObject();
                        context.Items["AppState"] = appState;
                        appState["type"] = "oauth2";
                        appState["name"] = authRequest["name"];
                        appState["author"] = authRequest["author"];
                        appState["trusted"] = authRequest["trusted"];
                        appState["request_id"] = requestId;
                        appState["consent"] = (oauth2Request.Groups[2].Value == ":consent");
                        var resource = new RESTfulResource();
                        resource.TrimScopesIn(authRequest);
                        appState["scope"] = authRequest["scope"];
                    }
                    else
                    {
                        oauthCookie.Expires = DateTime.Now.AddDays(-10);
                        oauthCookie.Value = null;
                        ApplicationServices.SetCookie(oauthCookie);
                    }
                }
                if (context.User.Identity.IsAuthenticated)
                    result = "<div data-app-role=\"page\"></div>";
            }
            return result;
        }

        public static bool AccessTokenToSelfEncryptedToken(string accessToken, out string selfEncryptedToken)
        {
            var result = true;
            selfEncryptedToken = accessToken;
            if (!string.IsNullOrEmpty(accessToken) && (accessToken.Length <= AccessTokenSize))
            {
                // 80 - access_token; 64 - refresh_token
                var tokenData = ApplicationServices.Create().AppDataReadAllText(OAuth2FileName("tokens/%", accessToken));
                if (tokenData != null)
                {
                    var tokenRequest = TextUtility.ParseYamlOrJson(tokenData);
                    selfEncryptedToken = ((string)(tokenRequest["token"]));
                    if (string.IsNullOrEmpty(accessToken))
                        result = false;
                    else
                    {
                        HttpContext.Current.Items["OAuth2_scope"] = Convert.ToString(tokenRequest["scope"]);
                        IdToken = ((JObject)(tokenRequest["id_token"]));
                    }
                }
                else
                    result = false;
            }
            return result;
        }

        public void AddLatestVersionLink(JObject result, DataCacheItem cacheItem)
        {
            if (IsImmutable && Hypermedia)
            {
                var latestVersionLink = ToApiName("latestVersionLink");
                var selfLink = ToApiName("selfLink");
                var links = result.Property(LinksKey);
                if (links == null)
                    return;
                JToken latestVersionObj = null;
                var latestVersionHref = "href";
                JToken selfControl = null;
                if (LinkStyle == "object")
                {
                    selfControl = links.Value[selfLink];
                    if (selfControl != null)
                    {
                        latestVersionObj = AddLink(latestVersionLink, "GET", links, ((string)(selfControl["href"])));
                        latestVersionObj.Remove();
                        selfControl.Parent.AddAfterSelf(latestVersionObj);
                        latestVersionObj = ((JProperty)(latestVersionObj)).Value;
                    }
                }
                else
                {
                    if (LinkStyle == "array")
                    {
                        var i = 0;
                        var linksArray = ((JArray)(links.Value));
                        foreach (JObject control in linksArray)
                        {
                            if (((string)(control["rel"])) == selfLink)
                            {
                                selfControl = control;
                                latestVersionObj = AddLink(latestVersionLink, "GET", links, ((string)(control["href"])));
                                linksArray.Remove(latestVersionObj);
                                linksArray.Insert((i + 1), latestVersionObj);
                                break;
                            }
                            i++;
                        }
                    }
                    else
                    {
                        selfControl = ((JObject)(links.Value)).Property(selfLink);
                        if (selfControl != null)
                        {
                            latestVersionObj = AddLink(latestVersionLink, "GET", links, ((string)(((JProperty)(selfControl)).Value)));
                            latestVersionObj.Remove();
                            selfControl.AddAfterSelf(latestVersionObj);
                            latestVersionObj = links.Value;
                            latestVersionHref = latestVersionLink;
                        }
                    }
                }
                if (latestVersionObj != null)
                {
                    var href = ((string)(latestVersionObj[latestVersionHref]));
                    if (href.Contains("?"))
                        href = href.Replace("?", string.Format("/{0}?", LatestVersionLink));
                    else
                        href = string.Format("{0}/{1}", href, LatestVersionLink);
                    latestVersionObj[latestVersionHref] = href;
                    AddLinkProperty(selfControl, "max-age", cacheItem.Duration);
                }
            }
        }
    }

    public partial class RESTfulResourceBase : RESTfulResourceConfiguration
    {

        public static SortedDictionary<string, OpConstraint> Operations = new SortedDictionary<string, OpConstraint>();

        public static SortedDictionary<string, string[]> OperationTypes = new SortedDictionary<string, string[]>();

        private ControllerConfiguration _masterConfig;

        private string _masterResource;

        private ControllerConfiguration _lookupConfig;

        private string _lookupResource;

        private string _controller;

        private string _specifiedView;

        private string _view;

        private XPathNavigator _viewNav;

        private ConfigDictionary _viewMap;

        private ConfigDictionary _excludedFields;

        private string _id;

        private XPathNavigator _action;

        private string _actionPathName;

        private List<FieldValue> _pk;

        private List<FieldValue> _filter;

        private string _followTo;

        private string _field;

        private XPathNavigator _fieldNav;

        private string _blobFileName;

        private List<string> _resourceLocation;

        private ConfigDictionary _fieldMap;

        private bool _isRoot;

        private bool _isCollection;

        private JObject _args;

        private JToken _result;

        private GroupCollection _customSchemaPath;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private JObject _customSchema;

        public string Controller
        {
            get
            {
                return _controller;
            }
            set
            {
                Config = GetConfig(value);
                if (!AllowController(Config.ControllerName))
                    RESTfulResource.ThrowError(403, "unauthorized", "Access to the resource '{0}' is denied.", Location);
                _controller = Config.ControllerName;
                _specifiedView = null;
            }
        }

        public string View
        {
            get
            {
                return _view;
            }
        }

        public string Id
        {
            get
            {
                return _id;
            }
        }

        public XPathNavigator Action
        {
            get
            {
                return _action;
            }
        }

        public string ActionPathName
        {
            get
            {
                return _actionPathName;
            }
        }

        public bool IsReport
        {
            get
            {
                return ((_action != null) && Regex.IsMatch(_action.GetAttribute("commandName", string.Empty), "^Report"));
            }
        }

        public List<FieldValue> PK
        {
            get
            {
                return _pk;
            }
        }

        public List<FieldValue> Filter
        {
            get
            {
                return _filter;
            }
        }

        public string FollowTo
        {
            get
            {
                return _followTo;
            }
        }

        public bool Following
        {
            get
            {
                return !string.IsNullOrEmpty(_followTo);
            }
        }

        public string Field
        {
            get
            {
                return _field;
            }
        }

        public string BlobFileName
        {
            get
            {
                return _blobFileName;
            }
        }

        public string Location
        {
            get
            {
                return ("/v2/" + string.Join("/", _resourceLocation));
            }
        }

        public ConfigDictionary FieldMap
        {
            get
            {
                return _fieldMap;
            }
        }

        public bool IsRoot
        {
            get
            {
                return _isRoot;
            }
        }

        public bool IsCollection
        {
            get
            {
                return _isCollection;
            }
        }

        public bool IsSingleton
        {
            get
            {
                return !IsCollection;
            }
        }

        public static string OAuth2Schema
        {
            get
            {
                var filename = "~/config/oauth2-schema.yaml";
                var schema = ((string)(HttpContext.Current.Cache[filename]));
                if (string.IsNullOrEmpty(schema))
                {
                    var fullPath = HttpContext.Current.Server.MapPath(filename);
                    schema = File.ReadAllText(fullPath);
                    HttpContext.Current.Cache.Add(filename, schema, new CacheDependency(fullPath), Cache.NoAbsoluteExpiration, Cache.NoSlidingExpiration, CacheItemPriority.Normal, null);
                }
                return schema;
            }
        }

        public JObject CustomSchema
        {
            get
            {
                return _customSchema;
            }
            set
            {
                _customSchema = value;
            }
        }

        protected void RetractLocation()
        {
            _resourceLocation.RemoveAt((_resourceLocation.Count - 1));
        }

        public JObject FindSchema(string schemaDef, string action)
        {
            var schema = ((JObject)(TextUtility.ParseYamlOrJson(Regex.Replace(schemaDef, "\\$Application", App.DisplayName), true)));
            var resourceSchema = ((JObject)(schema[action]));
            if (resourceSchema == null)
                foreach (var p in schema)
                    if (p.Key.Contains("$"))
                    {
                        var re = new Regex(("^" + Regex.Replace(p.Key, "\\$(\\w+)", "(?'$1'.+?)(?=/|$)")));
                        var m = re.Match(action);
                        if (m.Success && (m.Value.Length == action.Length))
                        {
                            _customSchemaPath = m.Groups;
                            resourceSchema = ((JObject)(schema[p.Key]));
                            break;
                        }
                    }
            return resourceSchema;
        }

        public virtual JObject LocalPathToSchema(List<string> localPath, string segment, int index)
        {
            JObject schema = null;
            if (RESTfulResource.IsOAuth)
            {
                OAuth = segment;
                OAuthMethod = string.Join("/", new ArraySegment<string>(localPath.ToArray(), (index + 1), ((localPath.Count - index) - 1)));
                schema = FindSchema(OAuth2Schema, OAuthMethodName);
                if (schema == null)
                {
                    var availableMethods = new List<string>();
                    foreach (var method in V2ServiceRequestHandlerBase.SupportedMethods)
                        if (FindSchema(OAuth2Schema, (method.ToLower() + ("/" + OAuthMethodPath))) != null)
                            availableMethods.Add(method);
                    if (availableMethods.Count > 0)
                        RESTfulResource.ThrowError("invalid_method", "Method {0} is not allowed with the '{1}' resource. Use {2} instead.", HttpMethod, OAuthMethodPath, string.Join(", ", availableMethods));
                    RESTfulResource.ThrowError("invalid_path", "Unknown OAuth resource '{0}' is specified.", OAuthMethodPath);
                }
            }
            return schema;
        }

        public virtual void Navigate(JObject args)
        {
            _args = args;
            _filter = new List<FieldValue>();
            _pk = new List<FieldValue>();
            _excludedFields = new ConfigDictionary();
            var url = HttpContext.Current.Request.Url;
            if (!ValidateApiUri(url))
            {
                HttpContext.Current.Response.StatusCode = 404;
                HttpContext.Current.Response.End();
            }
            var localPathString = url.LocalPath;
            if (localPathString.EndsWith("/"))
                RESTfulResource.ThrowError("invalid_uri", "The resource path cannot end with the '/' symbol.");
            var localPath = new List<string>(Regex.Split(localPathString, "\\/"));
            var pathIndex = 0;
            while (localPath[pathIndex] != "v2" && (pathIndex < localPath.Count))
                pathIndex++;
            pathIndex++;
            var isLatestVersion = false;
            if (!RESTfulResource.IsOAuth)
            {
                if (localPath[(localPath.Count - 1)] == LatestVersionLink)
                {
                    isLatestVersion = true;
                    localPath.RemoveAt((localPath.Count - 1));
                }
                var resourceFileName = Regex.Match(localPath[(localPath.Count - 1)], "^(\\w+)\\.(\\w+)$");
                if (resourceFileName.Success)
                    try
                    {
                        var blobIdentifier = Encoding.UTF8.GetString(TextUtility.FromBase64UrlEncoded(resourceFileName.Groups[1].Value)).Split('/');
                        if ((blobIdentifier.Length == 3) && ((blobIdentifier[1] == HttpUtility.UrlEncode(blobIdentifier[1])) && (blobIdentifier[2] == resourceFileName.Groups[2].Value.Substring(0, 1))))
                        {
                            localPath.RemoveAt((localPath.Count - 1));
                            if (localPath[(localPath.Count - 1)] == LatestVersionLink)
                            {
                                isLatestVersion = true;
                                localPath.RemoveAt((localPath.Count - 1));
                            }
                            localPath.Add(blobIdentifier[0]);
                            localPath.Add(blobIdentifier[1]);
                        }
                    }
                    catch (Exception)
                    {
                    }
            }
            _resourceLocation = new List<string>();
            var segment = string.Empty;
            var apiKey = string.Empty;
            try
            {
                while (pathIndex < localPath.Count)
                {
                    segment = localPath[pathIndex];
                    _resourceLocation.Add(segment);
                    if (_controller == null)
                    {
                        if (segment == "js")
                            StreamJSResource(PathArrayToString(localPath, (pathIndex + 1)));
                        CustomSchema = LocalPathToSchema(localPath, segment, pathIndex);
                        if (CustomSchema != null)
                            break;
                        var endpoint = PathArrayToString(localPath, pathIndex);
                        if (!AllowEndpoint(endpoint))
                            RESTfulResource.ThrowError(403, "invalid_path", "The endpoint '{0}' is not available.", endpoint);
                        if (string.IsNullOrEmpty(apiKey) && (RESTfulResource.PublicApiKeyInPath == segment))
                        {
                            apiKey = segment;
                            pathIndex++;
                            continue;
                        }
                        Controller = segment;
                        _isRoot = true;
                        _isCollection = true;
                    }
                    else
                    {
                        if (_view == null)
                        {
                            if (!GetView("auto", segment, out _view))
                            {
                                RetractLocation();
                                continue;
                            }
                        }
                        else
                        {
                            if (_id == null)
                            {
                                _isRoot = false;
                                if (!GetView("auto", segment, out _view))
                                {
                                    if ((segment == RootKey) && !Following)
                                    {
                                        _followTo = segment;
                                        _id = string.Empty;
                                        pathIndex++;
                                        continue;
                                    }
                                    else
                                    {
                                        _id = segment;
                                        LastEntity = _id;
                                        var pkValue = Regex.Split(_id, "\\s*_\\s*");
                                        var pkIndex = 0;
                                        foreach (var pkField in PK)
                                        {
                                            if (pkIndex < pkValue.Length)
                                            {
                                                var fieldType = _fieldMap[pkField.Name].GetAttribute("type", string.Empty);
                                                var v = pkValue[pkIndex];
                                                try
                                                {
                                                    pkField.Value = DataControllerBase.StringToValue(fieldType, v);
                                                }
                                                catch (Exception)
                                                {
                                                    if (FindAction(v) != null)
                                                        RESTfulResource.ThrowError("invalid_method", "Action '{0}' cannot be invoked with the {1} method. Use POST instead.", v, HttpMethod);
                                                    RESTfulResource.ThrowError("invalid_path", "Error converting '{0}' to '{1}' at {2} in the url.", v, fieldType, Location);
                                                }
                                            }
                                            else
                                                RESTfulResource.ThrowError("invalid_parameter", "Incorrect number of the key values in the url.");
                                            pkIndex++;
                                        }
                                        if (pkIndex == 0)
                                            RESTfulResource.ThrowError("invalid_path", "Object cannot be selected by resource key specified at {0} in the path.", Location);
                                        else
                                        {
                                            if (pkIndex < pkValue.Length)
                                                RESTfulResource.ThrowError("invalid_path", "Too many key values at {0} in the path.", Location);
                                        }
                                        var originalFilter = Filter;
                                        _filter = new List<FieldValue>(PK);
                                        _filter.AddRange(originalFilter);
                                        // read the current row to figure the value of the lookp field
                                        if (!string.IsNullOrWhiteSpace(_viewNav.GetAttribute("filter", string.Empty)))
                                        {
                                            var p = GetContext(PrimaryKeyToFieldNames());
                                            if (p.Rows.Count == 0)
                                                RESTfulResource.ThrowError(404, "invalid_path", "Entity {0} does not exist.", TrimLocationToIdentifier());
                                        }
                                        _field = null;
                                        _isCollection = false;
                                        GetView("singleton", DefaultView("singleton"), out _view);
                                        _specifiedView = null;
                                    }
                                }
                            }
                            else
                            {
                                if (_field == null)
                                {
                                    if (!GetView("auto", segment, out _view))
                                    {
                                        if (!FieldMap.TryGetValue(segment, out _fieldNav))
                                        {
                                            if ((segment == ChildrenKey) && !Following)
                                            {
                                                _followTo = segment;
                                                pathIndex++;
                                                continue;
                                            }
                                            else
                                            {
                                                if (FindAction(segment) != null)
                                                    RESTfulResource.ThrowError("invalid_method", "Action '{0}' cannot be used with the {1} method. Use POST instead.", ToApiFieldName(segment), HttpMethod);
                                                else
                                                    RESTfulResource.ThrowError(404, true, "invalid_path", "Unexpected field '{0}' is specifed at {1} in the path.", ToApiFieldName(segment), Location);
                                            }
                                        }
                                        LastEntity = segment;
                                        _field = _fieldNav.GetAttribute("name", string.Empty);
                                        var dataField = Config.SelectSingleNode("/c:dataController/c:views/c:view[@id='{0}']//c:dataField[@fieldName='{1}' or @aliasFieldName='{1}']", _view, _field);
                                        if (((dataField == null) && _fieldNav.GetAttribute("isPrimaryKey", string.Empty) != "true") || _excludedFields.ContainsKey(_field))
                                            RESTfulResource.ThrowError(403, true, "invalid_path", "Access to the field '{0}' is denied.", ToApiFieldName(_field));
                                        var dataType = _fieldNav.GetAttribute("type", string.Empty);
                                        if (!string.IsNullOrEmpty(_fieldNav.GetAttribute("onDemand", string.Empty)))
                                        {
                                            if ((pathIndex + 1) <= (localPath.Count - 1))
                                            {
                                                _blobFileName = localPath[(pathIndex + 1)];
                                                _resourceLocation.Add(BlobFileName);
                                                pathIndex++;
                                                if (pathIndex < (localPath.Count - 1))
                                                    RESTfulResource.ThrowError(403, true, "invalid_path", "The path must terminate at {0} filename.", Location);
                                                pathIndex++;
                                                continue;
                                            }
                                        }
                                        if ((dataType == "DataView") && _followTo != RootKey)
                                        {
                                            var p = GetContext(PrimaryKeyToFieldNames());
                                            if (p.Rows.Count == 0)
                                                RESTfulResource.ThrowError(404, "invalid_path", "Entity '{0}' does not exist.", TrimLocationToIdentifier());
                                            _followTo = null;
                                            // navigate to the DataView field collection
                                            _masterConfig = Config;
                                            _masterResource = segment;
                                            _lookupConfig = null;
                                            _lookupResource = null;
                                            var dataView = _fieldNav.SelectSingleNode("c:dataView", Config.Resolver);
                                            Controller = dataView.GetAttribute("controller", string.Empty);
                                            var parentPK = new List<FieldValue>(PK);
                                            RefreshConfigurationData();
                                            var filterFields = dataView.GetAttribute("filterFields", string.Empty);
                                            if (!string.IsNullOrEmpty(filterFields))
                                                foreach (var fkFieldName in Regex.Split(filterFields, "\\s*,\\s*"))
                                                    if (!string.IsNullOrEmpty(fkFieldName) && (_filter.Count < parentPK.Count))
                                                        _filter.Add(new FieldValue(fkFieldName, parentPK[_filter.Count].Value));
                                            _id = null;
                                            _field = null;
                                            _isCollection = true;
                                            GetView("collection", dataView.GetAttribute("view", string.Empty), out _view);
                                            _specifiedView = null;
                                        }
                                        else
                                        {
                                            var itemsDataControllerNav = _fieldNav.SelectSingleNode("c:items/@dataController", Config.Resolver);
                                            if (itemsDataControllerNav != null)
                                            {
                                                _masterConfig = null;
                                                _masterResource = null;
                                                _lookupConfig = Config;
                                                _lookupResource = segment;
                                                // navigate to the lookup singleton
                                                var dataValueFieldNav = _fieldNav.SelectSingleNode("c:items/@dataValueField", Config.Resolver);
                                                if (dataValueFieldNav != null)
                                                {
                                                    var lookupFields = new List<string>();
                                                    lookupFields.Add(dataValueFieldNav.Value);
                                                    var fkFields = new List<string>();
                                                    fkFields.Add(_field);
                                                    var copy = _fieldNav.SelectSingleNode("c:items/@copy", Config.Resolver);
                                                    if (copy != null)
                                                        foreach (Match m in Regex.Matches(copy.Value, "(\\w+)\\s*=\\s*(\\w+)"))
                                                        {
                                                            var fkFieldName = m.Groups[1].Value;
                                                            var fkFieldNav = Config.SelectSingleNode("/c:dataController/c:fields/c:field[@name='{0}' and c:items/@dataController='{1}']", fkFieldName, itemsDataControllerNav.Value);
                                                            if (fkFieldNav != null)
                                                            {
                                                                fkFields.Add(fkFieldName);
                                                                lookupFields.Add(m.Groups[2].Value);
                                                            }
                                                        }
                                                    if (Following && itemsDataControllerNav.Value != ControllerName)
                                                        RESTfulResource.ThrowError(404, "invalid_path", "Entity '{0}' does not have {1}.", Location, _followTo);
                                                    if (_followTo == RootKey)
                                                    {
                                                        _followTo = null;
                                                        _filter = new List<FieldValue>();
                                                        for (var i = 0; (i < fkFields.Count); i++)
                                                            _filter.Add(new FieldValue(fkFields[i], null));
                                                        _masterConfig = null;
                                                        _masterResource = null;
                                                        _lookupConfig = null;
                                                        _lookupResource = null;
                                                        _id = null;
                                                        _field = null;
                                                        _isCollection = true;
                                                    }
                                                    else
                                                    {
                                                        var p = GetContext(fkFields.ToArray());
                                                        if (p.Rows.Count == 0)
                                                            RESTfulResource.ThrowError(404, "invalid_path", "Entity '{0}' does not exist.", TrimLocationToIdentifier());
                                                        LastEntity = segment;
                                                        Controller = itemsDataControllerNav.Value;
                                                        RefreshConfigurationData();
                                                        if (Following)
                                                        {
                                                            _followTo = null;
                                                            _filter = new List<FieldValue>();
                                                            for (var i = 0; (i < fkFields.Count); i++)
                                                                _filter.Add(new FieldValue(fkFields[i], p.Rows[0][p.IndexOfField(lookupFields[i])]));
                                                            _masterConfig = Config;
                                                            _masterResource = null;
                                                            _lookupConfig = null;
                                                            _lookupResource = null;
                                                            _id = null;
                                                            _field = null;
                                                            _isCollection = true;
                                                            var childrenViewId = string.Empty;
                                                            var itemsDataViewNav = _fieldNav.SelectSingleNode("c:items/@dataView", Config.Resolver);
                                                            if (itemsDataViewNav != null)
                                                                childrenViewId = itemsDataViewNav.Value;
                                                            GetView("collection", childrenViewId, out _view);
                                                            _specifiedView = null;
                                                        }
                                                        else
                                                        {
                                                            for (var i = 0; (i < lookupFields.Count); i++)
                                                                foreach (var fvo in PK)
                                                                    if (fvo.Name == lookupFields[i])
                                                                    {
                                                                        fvo.Value = p.Rows[0][i];
                                                                        break;
                                                                    }
                                                            _filter = new List<FieldValue>(PK);
                                                            _id = PrimaryKeyToPath();
                                                            _field = null;
                                                            _isCollection = false;
                                                            GetView("singleton", null, out _view);
                                                        }
                                                    }
                                                }
                                                else
                                                    RESTfulResource.ThrowError(404, "invalid_path", "Unable to locate this resource.");
                                            }
                                            else
                                            {
                                                if (Following)
                                                    RESTfulResource.ThrowError(404, true, "invalid_path", "The name of the field is expected when following to {0}.", _followTo);
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    // All elements of the path are defined as controller/view/id/field.
                                    // This segment is either the view or an action.
                                    RESTfulResource.ThrowError("invalid_path", "Unexpected entity '{0}' in the path.", segment);
                                }
                            }
                        }
                    }
                    pathIndex++;
                }
            }
            catch (RESTfulResourceException ex)
            {
                EnsurePathProperties();
                if (((HttpMethod == "POST") || (HttpMethod == "GET")) && ((pathIndex >= (localPath.Count - 2)) && ((Config != null) && string.IsNullOrEmpty(_blobFileName))))
                {
                    if (pathIndex == (localPath.Count - 2))
                    {
                        // Expected: '/view/action'
                        var viewType = "singleton";
                        if (IsCollection)
                            viewType = "collection";
                        if (GetView(viewType, segment, out _view))
                        {
                            pathIndex++;
                            segment = localPath[pathIndex];
                            _resourceLocation.Add(segment);
                        }
                        else
                        {
                            if ((ex.HttpCode == 403) || (ex.HttpCode == 404))
                                throw ex;
                            RESTfulResource.ThrowError("invalid_path", "Entity '{0}' is not a valid view at {1} in the url.", segment, Location);
                        }
                    }
                    // Expected: '/view' or '/action' or '/id'
                    _action = FindAction(segment);
                    if (_action != null)
                    {
                        if (!IsReport && IsImmutable)
                            throw ex;
                        if (!IsPermittedActionIdentifier(segment))
                            RESTfulResource.ThrowError(403, false, "method-rejected", "Action '{0}' is not allowed.", segment);
                        _actionPathName = segment;
                        _field = null;
                        PathKey = null;
                        PathAction = string.Format("{0}/{1}", _action.SelectSingleNode("parent::*/@id").Value, _action.GetAttribute("id", string.Empty));
                        BuildActionSchema();
                    }
                    else
                    {
                        var a = FindAction(segment, false);
                        if (a != null)
                        {
                            if (!IsPermittedActionIdentifier(segment))
                                RESTfulResource.ThrowError(403, false, "method-rejected", "Action '{0}' is not allowed.", segment);
                            var moreInfo = string.Empty;
                            if ((a.GetAttribute("whenKeySelected", string.Empty) == "true") && IsCollection)
                                moreInfo = (moreInfo + " It requires a singleton.");
                            if (a.GetAttribute("whenKeySelected", string.Empty) != "true" && IsSingleton)
                                moreInfo = (moreInfo + " It requires a collection.");
                            if (string.IsNullOrEmpty(moreInfo) && !string.IsNullOrEmpty(a.GetAttribute("whenView", string.Empty)))
                                moreInfo = (moreInfo + " It requires another view.");
                            RESTfulResource.ThrowError(403, false, "method-rejected", "Action '{0}' is not allowed.{1}", segment, moreInfo);
                        }
                        else
                        {
                            if ((ex.HttpCode == 403) || (ex.HttpCode == 404))
                                throw ex;
                            if (!GetView(HttpMethod, segment, out _view))
                                RESTfulResource.ThrowError(400, true, "invalid_path", "Identifier '{0}' is not a valid view or action at {1} in the url.", segment, Location);
                        }
                    }
                }
                else
                    throw ex;
            }
            if (Following)
                RESTfulResource.ThrowError(404, true, "invalid_path", "The name of the field is expected when following to {0}.", _followTo);
            if (!string.IsNullOrEmpty(_controller))
            {
                if (string.IsNullOrEmpty(_view))
                    GetView(HttpMethod, "default", out _view);
                else
                {
                    if ((HttpMethod == "POST") && ((_action == null) && IsViewOfType(_view, "collection")))
                    {
                        // switch the view to the "POST" view createForm1 if the action is not specified
                        if (GetView(HttpMethod, "default", out _view))
                        {
                            if (segment != "default" && (segment != _view && IsViewOfType(segment, "collection")))
                                RESTfulResource.ThrowError(422, "invalid_path", "View '{0}' cannot be used to post data.", segment);
                        }
                        else
                            RESTfulResource.ThrowError("method_rejected", "Unable to post to this url.");
                    }
                }
                if (isLatestVersion)
                    RESTfulResource.LatestVersion = Controller;
            }
            EnsurePathProperties();
            if (OutputContentType.Contains("xml"))
                HttpContext.Current.Items["RESTfulConfiguration_xmlRoot"] = XmlRoot;
            if (string.IsNullOrEmpty(OAuth))
            {
                if (!AllowMethod(ControllerName, null))
                {
                    var method = HttpMethod;
                    var allowedMethods = new List<string>();
                    if (!string.IsNullOrEmpty(ActionPathName))
                        method = ActionPathName;
                    else
                        foreach (var m in V2ServiceRequestHandlerBase.SupportedMethods)
                            if (AllowMethod(ControllerName, m))
                                allowedMethods.Add(m);
                    var errorDescription = "Method {0} is not allowed.";
                    if (!string.IsNullOrEmpty(ActionPathName))
                        errorDescription = "Action {0} is not allowed.";
                    else
                    {
                        if (allowedMethods.Count > 0)
                            errorDescription = (errorDescription + " Use {1} instead.");
                    }
                    RESTfulResource.ThrowError(403, "invalid_method", errorDescription, method, string.Join(", ", allowedMethods));
                }
                foreach (var fieldName in _excludedFields.Keys)
                    _fieldMap.Remove(fieldName);
            }
        }

        protected virtual JObject BuildActionSchema()
        {
            List<DataField> paramFieldList = null;
            var confirmation = _action.GetAttribute("confirmation", string.Empty);
            if (!string.IsNullOrEmpty(confirmation))
            {
                var controllerName = string.Empty;
                var viewId = string.Empty;
                var m = Regex.Match(confirmation, "_controller\\s*=\\s*(?'ID'.+?)\\b");
                if (m.Success)
                    controllerName = m.Groups["ID"].Value;
                m = Regex.Match(confirmation, "_view\\s*=\\s*(?'ID'.+?)\\b");
                if (m.Success)
                    viewId = m.Groups["ID"].Value;
                if (!string.IsNullOrEmpty(controllerName))
                    try
                    {
                        paramFieldList = ToSchemaFields(controllerName, viewId);
                    }
                    catch (Exception ex)
                    {
                        RESTfulResource.ThrowError("invalid_action", "Action '{0}' cannot be confirmed with the controller '{1}'. {2}", ActionPathName, controllerName, ex.Message);
                    }
            }
            var input = new JObject();
            CustomSchema = new JObject(new JProperty("_input", input));
            var parametersObj = new JObject();
            input.Add(new JProperty(ParametersKey, parametersObj));
            var parametersProperties = new JObject();
            if (paramFieldList != null)
            {
                var parametersIsRequired = false;
                foreach (var f in paramFieldList)
                    if (!f.AllowNulls)
                    {
                        parametersIsRequired = true;
                        break;
                    }
                parametersObj.Add(new JProperty("required", parametersIsRequired));
                parametersObj.Add(new JProperty("properties", parametersProperties));
                AddFieldsToSchema(parametersProperties, paramFieldList);
            }
            else
                parametersObj.Add(new JProperty("properties", new JObject()));
            // create the 'collection' element in the '_input' key of action schema
            if (IsCollection)
            {
                var collectionSchema = new JObject();
                input.Add(new JProperty(CollectionKey, new JObject(new JProperty("array", true), new JProperty("properties", collectionSchema))));
                foreach (var fd in FieldMap)
                    if (fd.Value.GetAttribute("isPrimaryKey", string.Empty) == "true")
                    {
                        var f = new JObject();
                        f["type"] = fd.Value.GetAttribute("type", string.Empty);
                        var len = fd.Value.GetAttribute("len", string.Empty);
                        if (!string.IsNullOrEmpty(len))
                            f["length"] = int.Parse(len);
                        f["required"] = (fd.Value.GetAttribute("allowNulls", string.Empty) == "false");
                        collectionSchema.Add(new JProperty(ToApiFieldName(fd.Value.GetAttribute("name", string.Empty)), f));
                    }
            }
            input["*"] = true;
            return CustomSchema;
        }

        protected virtual void StreamJSResource(string segment)
        {
            var scriptInfo = Regex.Match(segment, "^(.+?)((\\.min)?\\.js)$");
            if (!scriptInfo.Success || scriptInfo.Groups[1].Value != "restful-2.0.1")
                RESTfulResource.ThrowError(404, "invalid_path", "Uknown script '{0}' is requested.", segment);
            var extension = scriptInfo.Groups[2].Value;
            if (!extension.StartsWith(".min") && AquariumExtenderBase.EnableMinifiedScript)
                extension = ".min.js";
            var context = HttpContext.Current;
            var response = context.Response;
            var js = File.ReadAllText(context.Server.MapPath(("~/js/sys/restful" + extension)));
            response.ContentType = "text/javascript";
            response.Headers.Remove("Set-Cookie");
            response.Cookies.Clear();
            response.Cache.SetCacheability(HttpCacheability.Public);
            response.Cache.SetMaxAge(TimeSpan.FromDays(365));
            response.Cache.SetProxyMaxAge(TimeSpan.FromDays(365));
            ApplicationServicesBase.CompressOutput(context, js);
            response.End();
        }

        protected virtual void EnsurePathProperties()
        {
            PathView = _view;
            if ((_fieldMap == null) && (Config != null))
                RefreshConfigurationData();
            if (!string.IsNullOrEmpty(_id))
                PathKey = _id;
            if (!string.IsNullOrEmpty(_field))
                PathField = _field;
        }

        protected virtual bool IsPermittedActionIdentifier(string id)
        {
            var a = _action;
            if (a == null)
            {
                a = FindAction(id, false);
                if (a == null)
                    return false;
            }
            var actionId = a.GetAttribute("id", string.Empty);
            if (Regex.IsMatch(actionId, "^a\\d+$"))
                return false;
            return ConfigDictionary.NormalizeKey(id).Equals(actionId, StringComparison.OrdinalIgnoreCase);
        }

        protected bool ValidateApiUri(Uri resource)
        {
            var domainTest = ((string)(ApplicationServicesBase.SettingsProperty("server.rest.domain")));
            if (!string.IsNullOrEmpty(domainTest))
            {
                var re = new Regex(domainTest);
                return re.IsMatch(resource.Authority);
            }
            return true;
        }

        protected virtual ViewPage GetContext(string[] fieldFilter)
        {
            var filter = new JObject();
            foreach (var fvo in this.Filter)
                filter.Add(new JProperty(fvo.Name, new JObject(new JProperty("equals", fvo.Value))));
            var r = new PageRequest()
            {
                Controller = _controller,
                View = _view,
                PageIndex = 0,
                PageSize = 1,
                FieldFilter = fieldFilter,
                RequiresMetaData = true,
                MetadataFilter = new string[] {
                    "fields"},
                Filter = ToFilter(filter)
            };
            return ControllerFactory.CreateDataController().GetPage(r.Controller, r.View, r);
        }

        protected virtual void RefreshConfigurationData()
        {
            _pk.Clear();
            _filter.Clear();
            _fieldMap = new ConfigDictionary();
            var fieldIterator = Config.Select("/c:dataController/c:fields/c:field");
            while (fieldIterator.MoveNext())
            {
                var fieldNav = fieldIterator.Current.Clone();
                var fieldName = fieldNav.GetAttribute("name", string.Empty);
                _fieldMap.Add(ToApiFieldName(fieldName), fieldNav);
                if (fieldIterator.Current.GetAttribute("isPrimaryKey", string.Empty) == "true")
                {
                    var fvo = new FieldValue(fieldName);
                    if (fieldIterator.Current.GetAttribute("readOnly", string.Empty) == "true")
                        fvo.ReadOnly = true;
                    _pk.Add(fvo);
                }
            }
            _viewMap = new ConfigDictionary();
            var viewIterator = Config.Select("/c:dataController/c:views/c:view");
            while (viewIterator.MoveNext())
            {
                if (IsTagged(viewIterator.Current, "rest-api-none"))
                    continue;
                var viewNav = viewIterator.Current.Clone();
                _viewMap.Add(ToApiFieldName(viewNav.GetAttribute("id", string.Empty)), viewNav);
            }
        }

        public virtual bool GetView(string type, string id, out string viewId)
        {
            var isExactMatch = false;
            if (_viewMap == null)
                RefreshConfigurationData();
            if ((type == "auto") || IsImmutable)
            {
                if (_isCollection)
                    type = "collection";
                else
                    type = "singleton";
            }
            var isDefault = (id == "default");
            if (isDefault)
                id = DefaultView(type);
            _viewNav = null;
            if (!string.IsNullOrEmpty(id) && _viewMap.TryGetValue(id, out _viewNav))
            {
                isExactMatch = true;
                _specifiedView = id;
            }
            else
            {
                id = _specifiedView;
                if (string.IsNullOrEmpty(id))
                    id = DefaultView(type);
                _viewMap.TryGetValue(id, out _viewNav);
            }
            if ((_viewNav == null) && IsRoot)
                foreach (var viewNav in _viewMap.Values)
                    if (IsTagged(viewNav, "rest-api-root"))
                    {
                        _viewNav = viewNav;
                        isExactMatch = isDefault;
                        break;
                    }
            if (_viewNav != null)
            {
                id = _viewNav.GetAttribute("id", string.Empty);
                if (IsTagged(_viewNav, "rest-api-root"))
                {
                    _isCollection = false;
                    _id = "1";
                    _specifiedView = id;
                }
                else
                {
                    var identifierIsCompatibleWithType = (id == DefaultView(type));
                    if (!identifierIsCompatibleWithType)
                        identifierIsCompatibleWithType = IsTagged(_viewNav, ("rest-api-" + type.ToLower()));
                    if (!identifierIsCompatibleWithType)
                    {
                        id = Location;
                        if (type == "collection")
                            RESTfulResource.ThrowError(422, false, "invalid_path", "View '{0}' cannot be used to retrieve a collection.", id);
                        if (type == "singleton")
                            RESTfulResource.ThrowError(422, false, "invalid_path", "View '{0}' cannot be used to retreive a singleton.", id);
                        if (type == "POST")
                            RESTfulResource.ThrowError(422, false, "invalid_path", "View '{0}' cannot be used to post data.", id);
                    }
                }
            }
            else
                RESTfulResource.ThrowError(400, true, "invalid_path", "There is no view compatible with the {0} method at {1} in the url.", HttpMethod, Location);
            viewId = id;
            if ((_resourceLocation.Count > 1) && (IsSameResource(id, _resourceLocation[(_resourceLocation.Count - 1)]) && IsSameResource(id, _resourceLocation[(_resourceLocation.Count - 2)])))
                RESTfulResource.ThrowError(400, true, "invalid_path", "View '{0}' is specified more than once in the path.", _resourceLocation[(_resourceLocation.Count - 1)]);
            if (_viewNav != null)
            {
                _excludedFields.Clear();
                var dataFieldIterator = _viewNav.Select("//c:dataField", Config.Resolver);
                while (dataFieldIterator.MoveNext())
                    if (IsTagged(dataFieldIterator.Current, "rest-api-none"))
                        _excludedFields[dataFieldIterator.Current.GetAttribute("fieldName", string.Empty)] = dataFieldIterator.Current.Clone();
            }
            return isExactMatch;
        }

        public static bool IsSameResource(string r1, string r2)
        {
            return r1.Replace("-", string.Empty).Replace("_", string.Empty).Equals(r2.Replace("-", string.Empty).Replace("_", string.Empty), StringComparison.CurrentCultureIgnoreCase);
        }

        public static bool IsTagged(XPathNavigator node, string tag)
        {
            var tagAttribute = "tags";
            if (node.Name == "dataField")
                tagAttribute = "tag";
            var tags = node.GetAttribute(tagAttribute, string.Empty);
            if (!string.IsNullOrEmpty(tags))
            {
                var tagList = Regex.Split(tags, "\\s+");
                return (Array.IndexOf(tagList, tag) >= 0);
            }
            return false;
        }

        public virtual string[] ToFilter(JObject args)
        {
            var filter = args["filter"];
            if (filter == null)
            {
                if (args["controller"] == null)
                    filter = args;
                else
                    return null;
            }
            var result = new List<string>();
            ToFilter(filter, result);
            return result.ToArray();
        }

        protected virtual void ToFilter(JToken filter, List<string> result)
        {
            if (!((filter is JArray)))
                filter = new JArray(filter);
            foreach (var fd in filter)
            {
                JObject filterDef;
                if (fd is JObject)
                    filterDef = ((JObject)(fd));
                else
                    filterDef = new JObject(new JProperty("filter", fd.ToString()));
                var hasMatchGroup = false;
                foreach (var matchGroupName in new string[] {
                        "_match_:$All$",
                        "_match_:$Any$",
                        "_doNotMatch_:$All$",
                        "_doNotMatch$Any$"})
                {
                    var groupInfo = Regex.Match(matchGroupName, "_(match|doNotMatch)_\\:(\\$(All|Any)\\$)", RegexOptions.IgnoreCase);
                    if (groupInfo.Success)
                    {
                        var matchGroup = filterDef[(groupInfo.Groups[1].Value + groupInfo.Groups[3].Value)];
                        if (matchGroup != null)
                        {
                            hasMatchGroup = true;
                            result.Add(matchGroupName.ToLower());
                            ToFilter(matchGroup, result);
                        }
                    }
                }
                if (!hasMatchGroup)
                {
                    var field = filterDef["field"];
                    if ((field != null) && (field is JValue))
                    {
                        // { "field": "Country", "value": "France }
                        // { "field": "Country", "op": "equals", "value": "France }
                        // { "field": "Country", "op": "notEmpty" }
                        // { "field": "UnitPrice", "op": "between", "value": [1,30] }
                        var fieldName = field.ToString();
                        JProperty op = null;
                        JProperty v = null;
                        JProperty url = null;
                        foreach (JProperty prop in filterDef.Properties())
                            if (prop.Name == "op")
                                op = prop;
                            else
                            {
                                if (prop.Name == "value")
                                    v = prop;
                                else
                                {
                                    if (prop.Name == "_url")
                                        url = prop;
                                    else
                                    {
                                        if (prop.Name != "field")
                                            RESTfulResource.ThrowError("invalid_filter", "Unexpected property '{0}' in the '{1}' field filter.", prop.Name, fieldName);
                                    }
                                }
                            }
                        filterDef.Remove("field");
                        if (op == null)
                            RESTfulResource.ThrowError("invalid_filter", "Missing property 'op' in the '{0}' field filter.", fieldName);
                        else
                            filterDef.Remove("op");
                        var newFilterDef = new JObject();
                        filterDef.Add(new JProperty(fieldName, newFilterDef));
                        JToken newValueDef = new JObject();
                        if (v != null)
                        {
                            newValueDef = v.Value;
                            filterDef.Remove("value");
                        }
                        newFilterDef.Add(new JProperty(op.Value.ToString(), newValueDef));
                        if (url != null)
                        {
                            filterDef.Remove("_url");
                            newFilterDef.Add(new JProperty("_url", true));
                        }
                    }
                    // Parse the canonical field filter in one of the folowing formats.
                    // {
                    //   "Country": {
                    //       "equals": "France"
                    // }
                    //
                    // {
                    //   "Country": {
                    //       "notEmpty": {}
                    //   }
                    // }
                    //
                    // {
                    //   "UnitPrice": {
                    //       "between": [10, 30]
                    //   }
                    // }
                    foreach (JProperty filterField in filterDef.Properties())
                    {
                        var fieldName = filterField.Name;
                        XPathNavigator fieldDef = null;
                        if (!_fieldMap.TryGetValue(fieldName, out fieldDef))
                            RESTfulResource.ThrowError(400, true, "invalid_filter", "Unexpected field '{0}' is specified in the filter.", fieldName);
                        JProperty filterOp = null;
                        var valueIsShortcut = ((filterField.Value is JArray) || (filterField.Value is JValue));
                        if (!valueIsShortcut)
                            foreach (JProperty prop in filterField.Value)
                                if (Operations.ContainsKey(prop.Name))
                                {
                                    if (filterOp == null)
                                        filterOp = prop;
                                    else
                                        RESTfulResource.ThrowError("invalid_filter", "Redundant operation '{0}' is specifed in the '{1}' field filter.", prop.Name, fieldName);
                                }
                                else
                                {
                                    if (prop.Name != "_url")
                                        RESTfulResource.ThrowError("invalid_filter", "Unexpected operation '{0}' is specifed in the '{1}' field filter.", prop.Name, fieldName);
                                }
                        if (filterOp == null)
                        {
                            if (valueIsShortcut)
                            {
                                filterOp = new JProperty("equals", filterField.Value);
                                filterField.Value = new JObject(filterOp);
                            }
                            else
                                RESTfulResource.ThrowError("invalid_filter", "Operation is not specifed in the '{0}' field filter.", fieldName);
                        }
                        var valueArray = new object[0];
                        var op = Operations[filterOp.Name];
                        object rawValue = filterOp.Value;
                        if (rawValue is JValue)
                        {
                            if (((JValue)(rawValue)).Type == JTokenType.Boolean)
                            {
                                if (Convert.ToBoolean(rawValue))
                                {
                                    if (string.IsNullOrEmpty(op.NegativeOp))
                                        RESTfulResource.ThrowError("invalid_filter", "Operation '{0}' is specifed in the '{1}' field filter does not have a negative counterpart.", filterOp.Name, fieldName);
                                    op = Operations[op.NegativeOp];
                                }
                            }
                            else
                            {
                                if (Convert.ToBoolean(filterField.Value["_url"]))
                                    rawValue = new JArray(Regex.Split(Convert.ToString(rawValue), "\\s*,\\s*"));
                                else
                                    rawValue = new JArray(rawValue);
                            }
                        }
                        else
                        {
                            if ((rawValue is JArray) && !string.IsNullOrEmpty(op.ArrayOp))
                                op = Operations[op.ArrayOp];
                        }
                        if (rawValue is JArray)
                            valueArray = ((JArray)(rawValue)).ToObject<object[]>();
                        if (valueArray.Length < op.MinValCount)
                        {
                            if (op.MinValCount == 1)
                                RESTfulResource.ThrowError("invalid_filter", "Operation '{0}' specifed in the '{1}' field filter requires at least 1 argument.", filterOp.Name, fieldName);
                            else
                                RESTfulResource.ThrowError("invalid_filter", "Operation '{0}' specifed in the '{1}' field filter requires at least {2} arguments.", filterOp.Name, fieldName, op.MinValCount);
                        }
                        if ((op.MaxValCount == 0) && (valueArray.Length > 0))
                            RESTfulResource.ThrowError("invalid_filter", "Operation '{0}' specifed in the '{1}' field filter cannot have arguments.", filterOp.Name, fieldName);
                        if (valueArray.Length > op.MaxValCount)
                        {
                            if (op.MaxValCount == 1)
                                RESTfulResource.ThrowError("invalid_filter", "Operation '{0}' specifed in the '{1}' field filter cannot have more than 1 argument.", filterOp.Name, fieldName);
                            else
                                RESTfulResource.ThrowError("invalid_filter", "Operation '{0}' specifed in the '{1}' field filter cannot have more than {2} arguments.", filterOp.Name, fieldName, op.MaxValCount);
                        }
                        var fieldDataType = fieldDef.GetAttribute("type", string.Empty);
                        if (!IsOperationCompatibleWithType(op.Op, fieldDataType))
                            RESTfulResource.ThrowError("invalid_filter", "Operation '{0}' specifed in the '{1}' field filter is not compatible with the data type {2}.", filterOp.Name, fieldName, fieldDataType);
                        var filterBuilder = new StringBuilder();
                        filterBuilder.Append(fieldName);
                        filterBuilder.Append(":");
                        filterBuilder.Append(op.Op);
                        if (op.Op.StartsWith("$"))
                            filterBuilder.Append("$");
                        if (valueArray.Length > 0)
                        {
                            var list = new List<string>();
                            for (var i = 0; (i < valueArray.Length); i++)
                            {
                                if (i > 0)
                                    list.Add(op.Join);
                                list.Add(DataControllerBase.ValueToString(valueArray[i]));
                            }
                            filterBuilder.Append(string.Join(string.Empty, list.ToArray()));
                        }
                        result.Add(filterBuilder.ToString());
                    }
                }
            }
        }

        protected virtual bool IsOperationCompatibleWithType(string op, string type)
        {
            var filterType = "Number";
            if ((type == "Time") || (type == "String"))
                filterType = "Text";
            else
            {
                if ((type == "Date") || ((type == "DateTime") || (type == "DateTimeOffset")))
                    filterType = "Date";
                else
                {
                    if (filterType == "Boolean")
                        filterType = "Boolean";
                }
            }
            return Array.IndexOf(OperationTypes[filterType], op) != -1;
        }

        public virtual void RemoveLinksFrom(JObject target)
        {
            var doRemove = false;
            foreach (var p in target.Properties())
                if (p.Name == LinksKey)
                    doRemove = true;
                else
                {
                    if (p.Value.Type == JTokenType.Object)
                        RemoveLinksFrom(((JObject)(p.Value)));
                    else
                    {
                        if (p.Value.Type == JTokenType.Array)
                            foreach (var elem in p.Value)
                                if (elem.Type == JTokenType.Object)
                                    RemoveLinksFrom(((JObject)(elem)));
                    }
                }
            if (doRemove)
                target.Remove(LinksKey);
        }

        public virtual ViewPage Execute(PageRequest request, JObject payload, JObject result)
        {
            if (HttpMethod == "PATCH")
            {
                if (IsCollection)
                    RESTfulResource.ThrowError(405, "invalid_method", "Collection cannot be patched.");
                Execute(request, payload, "Update");
            }
            if (HttpMethod == "PUT")
            {
                if (IsCollection)
                    RESTfulResource.ThrowError(405, "invalid_method", "Collection cannot be replaced.");
                Execute(request, payload, "Update");
            }
            if ((HttpMethod == "POST") || ((HttpMethod == "GET") && IsReport))
            {
                if (Action == null)
                {
                    if (IsSingleton)
                        RESTfulResource.ThrowError(405, "invalid_method", "Collection resource is expected for {0} method.", HttpMethod);
                    Execute(request, payload, "Insert");
                }
                else
                {
                    Execute(request, payload, Action.GetAttribute("commandName", string.Empty), Action.GetAttribute("commandArgument", string.Empty));
                    if (_result != null)
                    {
                        if (_result is JArray)
                            result[ToApiFieldName("collection")] = _result;
                        else
                            result[ToApiName("resultKey")] = _result;
                    }
                    if (IsCollection || IsReport)
                        return null;
                }
            }
            if (HttpMethod == "DELETE")
            {
                if (IsCollection)
                    RESTfulResource.ThrowError(405, "invalid_method", "Collection cannot be deleted.");
                if (_lookupConfig != null)
                    RESTfulResource.ThrowError(405, "invalid_method", "lookup cannot be deleted.");
                if (!string.IsNullOrEmpty(PathField))
                {
                    XPathNavigator blobField = null;
                    if (_fieldMap.TryGetValue(PathField, out blobField) && (blobField.GetAttribute("onDemand", string.Empty) == "true"))
                    {
                        var data = new byte[0];
                        Blob.Write(blobField.GetAttribute("onDemandHandler", string.Empty), PrimaryKeyToPath(), string.Empty, string.Empty, data);
                        return null;
                    }
                    RESTfulResource.ThrowError(405, "invalid_method", "Field value cannot be deleted.");
                }
                Execute(request, payload, "Delete");
                return null;
            }
            if (RequiresSchemaOnly)
                return null;
            return ControllerFactory.CreateDataController().GetPage(request.Controller, request.View, request);
        }

        public virtual void Execute(PageRequest request, JObject payload, string commandName)
        {
            Execute(request, payload, commandName, string.Empty);
        }

        public virtual void Execute(PageRequest request, JObject payload, string commandName, string commandArgument)
        {
            if (PK.Count == 0)
                RESTfulResource.ThrowError("invalid_path", "A resource with an identifier is expected.");
            if (FindAction(commandName) == null)
                RESTfulResource.ThrowError(405, true, "method_rejected", "Method '{0}' is now allowed for this resource.", HttpMethod);
            if (RequiresSchemaOnly)
                return;
            ViewPage existingViewPage = null;
            var context = HttpContext.Current;
            var conflictDetection = (Config.ConflictDetectionEnabled && (IsSingleton && (Action == null)));
            if ((commandName == "Update") || ((commandName == "Delete") || (commandName == "Custom")))
            {
                var ifMatch = context.Request.Headers["If-Match"];
                if (string.IsNullOrEmpty(ifMatch))
                {
                    if (conflictDetection)
                        RESTfulResource.ThrowError("method_rejected", "Set the 'If-Match' header to the value of the 'ETag' header returned with the fetched resource.");
                }
                else
                    try
                    {
                        var eTag = TextUtility.ToBase64UrlEncoded(Encoding.UTF8.GetBytes(TextUtility.Hash(EmbeddingEngine.Execute(ExtendRawUrlWith(string.Empty), null))));
                        if (eTag != ifMatch)
                            RESTfulResource.ThrowError(412, "method_rejected", "The entity has been changed since the last fetch. Specify the new 'ETag' value {0} in the 'If-Match' header.", eTag);
                    }
                    catch (WebException ex)
                    {
                        RESTfulResource.ThrowError(412, "method_rejected", "Unable to compare the 'If-Match' header with the 'ETag' of the {0} entity: {1}.", Location, ((HttpWebResponse)(ex.Response)).StatusDescription);
                    }
            }
            if (conflictDetection || (IsSingleton && ((Action != null) || Convert.ToBoolean(ApplicationServicesBase.SettingsProperty("server.rest.mutations.fetchExistingEntity", false)))))
                existingViewPage = ControllerFactory.CreateDataController().GetPage(request.Controller, request.View, request);
            var values = new List<FieldValue>(PK);
            var valuesMap = new SortedDictionary<string, FieldValue>();
            var defaultValueCount = values.Count;
            var a = new ActionArgs()
            {
                Controller = request.Controller,
                View = request.View,
                CommandName = commandName,
                CommandArgument = commandArgument,
                Path = PathAction
            };
            var pathFieldName = PathField;
            var pathFieldNameKey = pathFieldName;
            if (pathFieldName != null)
            {
                XPathNavigator pathFieldNav = null;
                _fieldMap.TryGetValue(pathFieldName, out pathFieldNav);
                pathFieldName = pathFieldNav.GetAttribute("name", string.Empty);
                pathFieldNameKey = ToApiNameTemplate("valueKey", pathFieldName);
                var fileKeys = context.Request.Files.Keys;
                if (pathFieldNav.GetAttribute("onDemand", string.Empty) == "true")
                {
                    var blobPage = GetContext(PrimaryKeyToFieldNames());
                    if (blobPage.Rows.Count < 1)
                        RESTfulResource.ThrowError("invalid_path", "Resource {0} does not exist.", TrimLocationToIdentifier());
                    if (fileKeys.Count != 1 || fileKeys[0] != pathFieldNameKey)
                        RESTfulResource.ThrowError(403, "invalid_argument", "Specify the '{0}' file in the 'multipart/form-data' body.", pathFieldNameKey);
                }
                else
                {
                    if (payload[pathFieldNameKey] == null)
                        RESTfulResource.ThrowError(403, "invalid_argument", "Field '{0}' is expected in the body.", pathFieldNameKey);
                    if (fileKeys.Count > 0)
                        RESTfulResource.ThrowError(403, "invalid_argument", "File '{0}' is not allowed in the body.", fileKeys[0]);
                }
            }
            var errors = new List<RESTfulResourceException>();
            // scan the duplicate field names in the payload: productId, product_id, productid, ProductID
            var usedKeys = new SortedDictionary<string, string>();
            foreach (var p in payload.Properties())
                try
                {
                    XPathNavigator fieldNav = null;
                    if (_fieldMap.TryGetValue(p.Name, out fieldNav))
                    {
                        var fieldName = fieldNav.GetAttribute("name", string.Empty);
                        var firstUseCase = string.Empty;
                        if (usedKeys.TryGetValue(fieldName, out firstUseCase))
                            RESTfulResource.ThrowError(403, "invalid_argument", "Field '{0}' specified in the body is the duplicate of '{1}'.", p.Name, firstUseCase);
                        else
                            usedKeys[fieldName] = p.Name;
                    }
                }
                catch (RESTfulResourceException ex)
                {
                    errors.Add(ex);
                }
            if (errors.Count > 0)
                throw new RESTfulResourceException(errors);
            // Ensure that the filter values are not in conflict with the payload. Applied to the primery key field value and master-detail foreign key fields.
            if (_masterConfig != null)
                foreach (var fvo in Filter)
                {
                    var propName = ToApiFieldName(fvo.Name);
                    var propToken = payload[propName];
                    if ((propToken != null) && Convert.ToString(propToken) != Convert.ToString(fvo.Value))
                        RESTfulResource.ThrowError(403, "invalid_argument", "Value of the '{0}' field specified in the body does not match the master entity in the url.", propName);
                    // resolve the missing field values that do not exist in the filter
                    if (propToken == null)
                    {
                        payload.Add(new JProperty(propName, fvo.Value));
                        if (PK.IndexOf(fvo) == -1)
                            defaultValueCount++;
                    }
                }
            // create default values for Insert command
            if (commandName == "Insert")
            {
                request.Inserting = true;
                var newViewPage = ControllerFactory.CreateDataController().GetPage(request.Controller, request.View, request);
                request.Inserting = false;
                for (var fieldIndex = 0; (fieldIndex < newViewPage.NewRow.Length); fieldIndex++)
                {
                    var v = newViewPage.NewRow[fieldIndex];
                    if (v != null)
                    {
                        var field = newViewPage.Fields[fieldIndex];
                        var propName = ToApiFieldName(field.Name);
                        var propToken = payload[propName];
                        if (propToken == null)
                        {
                            SetPropertyValue(payload, propName, v);
                            defaultValueCount++;
                        }
                    }
                }
            }
            // lookup the missing foreign key field values by the "alias" and "copy" fields of the payload
            if (HttpMethod != "DELETE")
            {
                var lookupIterator = Config.Select("/c:dataController/c:fields/c:field[c:items/@dataController]");
                while (lookupIterator.MoveNext())
                {
                    var fieldName = lookupIterator.Current.GetAttribute("name", string.Empty);
                    var dataFieldNav = Config.SelectSingleNode("/c:dataController/c:views/c:view[@id='{0}']//c:dataField[@fieldName='{1}']", PathView, fieldName);
                    var propName = ToApiFieldName(fieldName);
                    XPathNavigator lookupNav = null;
                    if ((dataFieldNav != null) && (payload[propName] == null))
                    {
                        if (_fieldMap.TryGetValue(fieldName, out lookupNav))
                        {
                            var aliasFieldName = dataFieldNav.GetAttribute("aliasFieldName", string.Empty);
                            if (string.IsNullOrEmpty(aliasFieldName))
                                aliasFieldName = fieldName;
                            var aliasNav = Config.SelectSingleNode("/c:dataController/c:fields/c:field[@name='{0}']", aliasFieldName);
                            var aliasPropName = ToApiFieldName(aliasFieldName);
                            var aliasPropValue = GetPropertyValue(payload, aliasPropName, aliasNav.GetAttribute("type", string.Empty));
                            if (aliasPropValue != null)
                            {
                                var itemsNav = lookupNav.SelectSingleNode("c:items", Config.Resolver);
                                var lookupController = itemsNav.GetAttribute("dataController", string.Empty);
                                var viewId = itemsNav.GetAttribute("dataView", string.Empty);
                                var dataValueField = itemsNav.GetAttribute("dataValueField", string.Empty);
                                var dataTextField = itemsNav.GetAttribute("dataTextField", string.Empty);
                                if (string.IsNullOrEmpty(dataTextField))
                                    dataTextField = dataValueField;
                                var copy = itemsNav.GetAttribute("copy", string.Empty);
                                // prepare the lookup mapping
                                var payloadLookupFields = new List<string>();
                                payloadLookupFields.Add(fieldName);
                                payloadLookupFields.Add(aliasFieldName);
                                var lookupFieldFilter = new List<string>();
                                lookupFieldFilter.Add(dataValueField);
                                lookupFieldFilter.Add(dataTextField);
                                var lookupFilter = new List<string>();
                                lookupFilter.Add((dataTextField + (":=" + DataControllerBase.ValueToString(aliasPropValue))));
                                // enumerate the "copy" fields to enhance the lookup precision
                                if (!string.IsNullOrEmpty(copy))
                                {
                                    var m = Regex.Match(copy, "(\\w+)\\s*=\\s*(\\w+)");
                                    while (m.Success)
                                    {
                                        var copyPropName = m.Groups[1].Value;
                                        var lookupFieldName = m.Groups[2].Value;
                                        var copyFieldNav = Config.SelectSingleNode("/c:dataController/c:fields/c:field[@name='{0}']", copyPropName);
                                        if (copyFieldNav != null)
                                        {
                                            var copyPropValue = GetPropertyValue(payload, ToApiFieldName(copyPropName), copyFieldNav.GetAttribute("type", string.Empty));
                                            payloadLookupFields.Add(copyPropName);
                                            lookupFieldFilter.Add(lookupFieldName);
                                            if (copyPropValue != null)
                                                lookupFilter.Add((lookupFieldName + (":=" + DataControllerBase.ValueToString(copyPropValue))));
                                        }
                                        m = m.NextMatch();
                                    }
                                }
                                var lookupRequest = new PageRequest(0, 1, null, lookupFilter.ToArray())
                                {
                                    Controller = lookupController,
                                    View = viewId,
                                    RequiresMetaData = true,
                                    MetadataFilter = new string[] {
                                        "fields"},
                                    FieldFilter = lookupFieldFilter.ToArray()
                                };
                                var lookupPage = ControllerFactory.CreateDataController().GetPage(lookupRequest.Controller, lookupRequest.View, lookupRequest);
                                if (lookupPage.Rows.Count > 0)
                                    for (var i = 0; (i < lookupPage.Fields.Count); i++)
                                        SetPropertyValue(payload, payloadLookupFields[lookupFieldFilter.IndexOf(lookupPage.Fields[i].Name)], lookupPage.Rows[0][i]);
                            }
                        }
                    }
                }
            }
            // ensure that all required fields are present when POST or PUT is executed
            if ((HttpMethod == "POST") || ((HttpMethod == "PUT") && string.IsNullOrEmpty(PathField)))
            {
                var dataFieldIterator = Config.Select("/c:dataController/c:views/c:view[@id='{0}']//c:dataField", PathView);
                while (dataFieldIterator.MoveNext())
                    try
                    {
                        var fieldName = dataFieldIterator.Current.GetAttribute("fieldName", string.Empty);
                        var fieldNav = Config.SelectSingleNode("/c:dataController/c:fields/c:field[@name='{0}']", fieldName);
                        if (fieldNav == null)
                            RESTfulResource.ThrowError(500, true, "invalid_controller", "Field '{0}' is not defined in the '{1}' controller.", fieldName, ControllerName);
                        var isPrimaryKey = (fieldNav.GetAttribute("isPrimaryKey", string.Empty) == "true");
                        var isReadOnly = (fieldNav.GetAttribute("readOnly", string.Empty) == "true");
                        var allowNulls = fieldNav.GetAttribute("allowNulls", string.Empty) != "false";
                        var hasDefault = !string.IsNullOrEmpty(fieldNav.GetAttribute("default", string.Empty));
                        var propName = ToApiFieldName(fieldName);
                        if (isPrimaryKey && !isReadOnly)
                        {
                            // set the primay key field value
                            foreach (var fvo in PK)
                                if ((fvo.Name == fieldName) && (payload[propName] == null))
                                {
                                    SetPropertyValue(payload, propName, fvo.Value);
                                    break;
                                }
                        }
                        else
                        {
                            if (((!allowNulls && !isReadOnly) && (payload[propName] == null)) && (!hasDefault && (Action == null)))
                                RESTfulResource.ThrowError(403, true, "invalid_argument", "Field '{0}' is expected in the body.", propName);
                        }
                    }
                    catch (RESTfulResourceException ex)
                    {
                        errors.Add(ex);
                    }
                if (errors.Count > 0)
                    throw new RESTfulResourceException(errors);
            }
            // inject the properties with the null value for the missing properties of the PUT method
            if ((HttpMethod == "PUT") && string.IsNullOrEmpty(PathField))
            {
                var dataFieldIterator = Config.Select("/c:dataController/c:views/c:view[@id='{0}']//c:dataField", PathView);
                while (dataFieldIterator.MoveNext())
                {
                    var fieldName = dataFieldIterator.Current.GetAttribute("fieldName", string.Empty);
                    var propName = ToApiFieldName(fieldName);
                    if (payload[propName] == null)
                        SetPropertyValue(payload, propName, null);
                }
            }
            // validate the values
            var systemPayloadKeys = new List<string>(new string[] {
                        EmbeddedKey,
                        LinksKey,
                        SchemaKey});
            if (Action != null)
                systemPayloadKeys.Add(ParametersKey);
            if (IsCollection && (Action != null))
                systemPayloadKeys.Add(CollectionKey);
            foreach (var p in payload.Properties())
                try
                {
                    var propName = p.Name;
                    if (propName == pathFieldNameKey)
                        propName = pathFieldName;
                    XPathNavigator fieldNav = null;
                    if (_fieldMap.TryGetValue(propName, out fieldNav))
                    {
                        if (!string.IsNullOrEmpty(pathFieldName) && propName != pathFieldName)
                            RESTfulResource.ThrowError(403, "invalid_argument", "Field '{0}' is not allowed in the the body.", propName);
                        var fieldName = fieldNav.GetAttribute("name", string.Empty);
                        var isReadOnly = (fieldNav.GetAttribute("readOnly", string.Empty) == "true");
                        var allowNulls = fieldNav.GetAttribute("allowNulls", string.Empty) != "false";
                        var fieldType = fieldNav.GetAttribute("type", string.Empty);
                        var hasDefault = !string.IsNullOrEmpty(fieldNav.GetAttribute("default", string.Empty));
                        if (fieldNav.GetAttribute("isPrimaryKey", string.Empty) != "true")
                        {
                            var dataField = Config.SelectSingleNode("/c:dataController/c:views/c:view[@id='{0}']//c:dataField[@fieldName='{1}' or @aliasFieldName='{1}']", PathView, fieldName);
                            if (dataField == null)
                            {
                                var accessDenied = true;
                                foreach (var fvo in Filter)
                                    if (fvo.Name == fieldName)
                                    {
                                        accessDenied = false;
                                        values.Add(fvo);
                                        break;
                                    }
                                if (accessDenied)
                                    RESTfulResource.ThrowError(403, true, "invalid_argument", "Access to the field '{0}' is denied.", ToApiFieldName(fieldName));
                                else
                                    continue;
                            }
                            if (fieldType == "DataView")
                            {
                                // process the DataView field collection - do nothing
                                fieldType = "DataView";
                            }
                            else
                            {
                                if (fieldNav.GetAttribute("onDemand", string.Empty) == "true")
                                {
                                    if ((p.Value.Type == JTokenType.String) && Convert.ToString(p.Value).StartsWith(ToServiceUrl("/v2/")))
                                        continue;
                                    RESTfulResource.ThrowError(403, true, "invalid_argument", "Blob field '{0}' cannot be specified in the body. Specify its value as the file in the 'multipart/form-data' instead.", ToApiFieldName(fieldName));
                                }
                                else
                                {
                                    object v = null;
                                    if (p.Value.Type != JTokenType.Null)
                                        try
                                        {
                                            v = DataControllerBase.StringToValue(fieldType, Convert.ToString(p.Value));
                                        }
                                        catch (Exception)
                                        {
                                            RESTfulResource.ThrowError("invalid_argument", "The value of the field '{0}' is invalid. Error converting '{1}' to '{2}'.", p.Name, p.Value, fieldType);
                                        }
                                    if ((v == null) && (!allowNulls && !hasDefault))
                                        RESTfulResource.ThrowError(400, true, "invalid_argument", "The value of the field '{0}' cannot be null.", p.Name);
                                    if (v is string)
                                    {
                                        var len = fieldNav.GetAttribute("length", string.Empty);
                                        if (!string.IsNullOrEmpty(len) && (Convert.ToInt32(len) < ((string)(v)).Length))
                                            RESTfulResource.ThrowError("invalid_argument", "The maximum length of the field '{0}' is {1}.", p.Name, len);
                                    }
                                    var fvo = new FieldValue(fieldName);
                                    if (isReadOnly)
                                    {
                                        fvo.OldValue = v;
                                        fvo.ReadOnly = true;
                                    }
                                    else
                                    {
                                        fvo.NewValue = v;
                                        fvo.Modified = true;
                                    }
                                    values.Add(fvo);
                                }
                            }
                        }
                        else
                            foreach (var pkField in PK)
                                if (fieldName == pkField.Name)
                                {
                                    if (pkField.Value == null)
                                    {
                                        if (!isReadOnly && (p.Value.Type == JTokenType.Null))
                                            RESTfulResource.ThrowError(400, true, "invalid_argument", "The value of the key field '{0}' cannot be null.", p.Name);
                                        if ((isReadOnly && (commandName == "Insert")) && p.Value.Type != JTokenType.Null)
                                            RESTfulResource.ThrowError(403, true, "invalid_argument", "Field '{0}' can not have a value specified in the body.", propName);
                                        if (p.Value.Type != JTokenType.Null)
                                        {
                                            pkField.NewValue = DataControllerBase.StringToValue(fieldType, Convert.ToString(p.Value));
                                            pkField.OldValue = null;
                                            pkField.Modified = true;
                                        }
                                    }
                                    if (Convert.ToString(pkField.Value) != Convert.ToString(p.Value))
                                        RESTfulResource.ThrowError("invalid_argument", "The value of the field '{0}' does not match the entity path.", p.Name);
                                    if ((HttpMethod == "PUT") && (commandName == "Insert"))
                                    {
                                        if (isReadOnly)
                                            RESTfulResource.ThrowError(404, "invalid_path", "Entity {0} does not exist.", TrimLocationToIdentifier());
                                        pkField.NewValue = pkField.OldValue;
                                        pkField.OldValue = null;
                                        pkField.Modified = true;
                                    }
                                    break;
                                }
                    }
                    else
                    {
                        if (!systemPayloadKeys.Contains(p.Name))
                            RESTfulResource.ThrowError(400, true, "invalid_argument", "Unexpected field '{0}' is specifed in the body.", p.Name);
                    }
                }
                catch (RESTfulResourceException ex)
                {
                    errors.Add(ex);
                }
            // verify the file keys
            foreach (string blobFieldName in context.Request.Files.Keys)
                if (!string.IsNullOrEmpty(blobFieldName))
                {
                    XPathNavigator fieldNav = null;
                    if (_fieldMap.TryGetValue(blobFieldName, out fieldNav))
                    {
                        if (!(((fieldNav.GetAttribute("type", string.Empty) == "Byte[]") && (fieldNav.GetAttribute("onDemand", string.Empty) == "true"))) || (fieldNav.GetAttribute("readOnly", string.Empty) == "true"))
                            RESTfulResource.ThrowError(400, true, "invalid_argument", "Field '{0}' cannot accept the binary data specified as the file in the form.", blobFieldName);
                    }
                    else
                    {
                        if (string.IsNullOrWhiteSpace(PathField))
                            RESTfulResource.ThrowError(400, true, "invalid_argument", "Unexpected field '{0}' is specifed as the file in the 'multipart/form-data' body.", blobFieldName);
                    }
                }
            if (errors.Count > 0)
                throw new RESTfulResourceException(errors);
            if (((defaultValueCount == values.Count) && (HttpMethod == "PATCH")) && ((Action == null) && (context.Request.Files.Count == 0)))
                RESTfulResource.ThrowError(400, true, "invalid_argument", "At least one non-key field must be specified in the body.");
            // assign the "old" values for conflict detection and custom actions
            if (existingViewPage != null)
            {
                if (existingViewPage.Rows.Count == 0)
                {
                    if (!string.IsNullOrEmpty(ActionPathName))
                        RetractLocation();
                    RESTfulResource.ThrowError(404, "invalid_path", "Entity {0} does not exist.", TrimLocationToIdentifier());
                }
                foreach (var fvo in values)
                    valuesMap[fvo.Name] = fvo;
                foreach (var f in existingViewPage.Fields)
                    if ((!f.IsPrimaryKey && !f.OnDemand) && f.Type != "DataView")
                    {
                        FieldValue fvo = null;
                        if (!valuesMap.TryGetValue(f.Name, out fvo))
                        {
                            fvo = new FieldValue(f.Name);
                            values.Add(fvo);
                        }
                        fvo.OldValue = existingViewPage.Rows[0][existingViewPage.IndexOfField(f.Name)];
                        if (fvo.Modified && (fvo.NewValue == fvo.OldValue))
                            fvo.Modified = false;
                        if (f.ReadOnly)
                            fvo.ReadOnly = true;
                    }
            }
            var selectedValues = new List<string>();
            if (IsSingleton)
                foreach (var fvo in PK)
                    selectedValues.Add(Convert.ToString(fvo.Value));
            try
            {
                ValidateActionCollection(payload, values, selectedValues);
                ValidateActionParameters(payload, values);
                a.Values = values.ToArray();
                a.Sequence = 0;
                a.Filter = ToFilter(_args);
                a.SelectedValues = selectedValues.ToArray();
                ValidateActionArguments(payload, a);
            }
            catch (RESTfulResourceException ex)
            {
                throw ex;
            }
            catch (Exception ex)
            {
                RESTfulResource.ThrowError(400, true, "invalid_argument", ex.Message);
            }
            // *** stream the report out ***
            if (IsReport && !RequiresSchema)
            {
                var reportFilter = new List<string>(a.Filter);
                if ((a.SelectedValues.Length > 0) && (PK.Count > 0))
                    reportFilter.Add(((PK[0].Name + ":$in$") + string.Join("$or$", a.SelectedValues)));
                var argumentParts = Regex.Split(commandArgument, "\\s*,\\s*");
                var reportFormat = Regex.Match(commandName, "^Report(As(?'Format'Pdf|Image|Word|Excel))$");
                var reportArgs = new ReportArgs()
                {
                    Controller = request.Controller,
                    View = request.View,
                    FilterRaw = reportFilter.ToArray(),
                    SortExpression = request.SortExpression,
                    TemplateName = argumentParts[0],
                    Format = reportFormat.Groups["Format"].Value
                };
                var reportData = ReportBase.Execute(reportArgs, a);
                context.Response.ContentType = reportArgs.MimeType;
                context.Response.AddHeader("Content-Length", reportData.Length.ToString());
                context.Response.AddHeader("Content-Disposition", string.Format("attachment;filename={0}", reportArgs.FileName));
                context.Response.OutputStream.Write(reportData, 0, reportData.Length);
                return;
            }
            // *** proceed to execute the action in the context of a transaction ***
            var log = new List<ActionArgs>();
            log.Add(a);
            var tm = new TransactionManager();
            var result = tm.Commit(log);
            if ((result.Errors != null) && (result.Errors.Length > 0))
            {
                if (result.RowNotFound)
                {
                    if (HttpMethod == "PUT")
                        Execute(request, payload, "Insert");
                    else
                        RESTfulResource.ThrowError(404, "invalid_path", "Entity {0} does not exist.", TrimLocationToIdentifier());
                }
                else
                    RESTfulResource.ThrowError(500, "method_rejected", string.Join(" ", result.Errors));
            }
            else
            {
                if (commandName == "Insert")
                {
                    _isCollection = false;
                    _id = PrimaryKeyToPath();
                    _view = DefaultView("singleton");
                    var startWith = PathField;
                    if (string.IsNullOrEmpty(startWith))
                        startWith = ControllerResource;
                    LastEntity = _id;
                    RawUrl = ReplaceRawUrlWith(startWith, false, "{0}/{1}", startWith, _id);
                    EnsurePathProperties();
                    // a resource was created
                    context.Response.StatusCode = 201;
                    context.Response.Headers["Location"] = RawUrl;
                    var newFilter = new JObject();
                    foreach (var fvo in PK)
                        newFilter.Add(new JProperty(fvo.Name, new JObject(new JProperty("equals", fvo.Value))));
                    request.Filter = ToFilter(newFilter);
                    request.RequiresRowCount = false;
                    request.PageSize = 1;
                }
                if (Action != null)
                {
                    var actionResult = new JObject();
                    foreach (var fvo in result.Values)
                    {
                        var v = fvo.Value;
                        if (v is DateTime)
                            v = ((DateTime)(v)).ToString("o");
                        SetPropertyValue(actionResult, fvo.Name, v);
                    }
                    var resultSet = ((DataTable)(HttpContext.Current.Items["BusinessRules_ResultSet"]));
                    if (resultSet != null)
                    {
                        var data = new JArray();
                        foreach (DataRow row in resultSet.Rows)
                        {
                            var item = new JObject();
                            for (var i = 0; (i < row.ItemArray.Length); i++)
                            {
                                var propName = ToApiFieldName(resultSet.Columns[i].ColumnName);
                                var v = row.ItemArray[i];
                                if (v is DateTime)
                                    v = ((DateTime)(v)).ToString("o");
                                if (v == null)
                                    item[propName] = null;
                                else
                                    item[propName] = JToken.FromObject(v);
                            }
                            data.Add(item);
                        }
                        var resultIsCollection = false;
                        if (IsCollection)
                        {
                            resultIsCollection = (PK.Count == 0);
                            foreach (var f in PK)
                                if (resultSet.Columns.Contains(f.Name))
                                    resultIsCollection = true;
                            if (resultIsCollection)
                                foreach (DataColumn c in resultSet.Columns)
                                    if (!FieldMap.ContainsKey(c.ColumnName))
                                    {
                                        resultIsCollection = false;
                                        break;
                                    }
                        }
                        if (resultIsCollection)
                        {
                            _result = data;
                            if (data.Count > 0)
                            {
                                var nullValues = new List<string>();
                                foreach (var f in FieldMap)
                                {
                                    var fieldName = ToApiFieldName(f.Value.GetAttribute("name", string.Empty));
                                    if (!((JObject)(data[0])).ContainsKey(fieldName))
                                        nullValues.Add(fieldName);
                                }
                                foreach (var obj in data)
                                    foreach (var fieldName in nullValues)
                                        obj[fieldName] = null;
                            }
                        }
                        else
                        {
                            if ((actionResult.Count == 0) && (data.Count == 1))
                                foreach (JProperty p in data[0])
                                    SetPropertyValue(actionResult, p.Name, p.Value);
                            else
                                actionResult[ToApiName("resultSetKey")] = data;
                        }
                    }
                    if (actionResult.Count > 0)
                        _result = actionResult;
                }
                ExecuteFiles(request, payload, commandName, commandArgument);
            }
        }

        protected void ValidateActionParameters(JObject payload, List<FieldValue> values)
        {
            var parameters = payload[ParametersKey];
            if (parameters != null)
            {
                if (parameters.Type != JTokenType.Object)
                    RESTfulResource.ThrowError(400, true, "invalid_parameters", "Invalid definition of '{0}'. An object is expected.", ParametersKey);
            }
            if (Action != null)
                ValidateActionParameters(payload, ((JObject)(parameters)), values);
        }

        protected virtual void ValidateActionParameters(JObject payload, JObject parameters, List<FieldValue> values)
        {
            if (parameters != null)
            {
                // enumerate parameters with the optional validation against the confirmation data controller
                foreach (var p in parameters.Properties())
                {
                    string dataType = null;
                    values.Add(new FieldValue(("Parameters_" + ToDataFieldName(p.Name)), GetPropertyValue(parameters, p.Name, dataType)));
                }
            }
        }

        protected virtual void ValidateActionCollection(JObject payload, List<FieldValue> values, List<string> selectedValues)
        {
            if (IsCollection && (Action != null))
            {
                var collection = payload[CollectionKey];
                if ((collection != null) && collection.Type != JTokenType.Null)
                {
                    if (collection.Type != JTokenType.Array)
                        RESTfulResource.ThrowError(400, true, "invalid_argument", "Invalid definition of '{0}'. An array is expected.", CollectionKey);
                    foreach (var item in collection)
                    {
                        var itemKey = new List<string>();
                        if (item is JObject)
                            foreach (var p in ((JObject)(item)).Properties())
                            {
                                XPathNavigator fieldNav = null;
                                if (_fieldMap.TryGetValue(p.Name, out fieldNav))
                                {
                                    if (fieldNav.GetAttribute("isPrimaryKey", string.Empty) == "true")
                                    {
                                        var fieldName = fieldNav.GetAttribute("name", string.Empty);
                                        var keyValue = GetPropertyValue(((JObject)(item)), p.Name, fieldNav.GetAttribute("type", string.Empty));
                                        itemKey.Add(Convert.ToString(keyValue));
                                        if (payload[p.Name] == null)
                                        {
                                            // copy the first selected value to the values array
                                            SetPropertyValue(payload, p.Name, keyValue);
                                            foreach (var fvo in values)
                                                if (fvo.Name == fieldName)
                                                {
                                                    fvo.Value = keyValue;
                                                    break;
                                                }
                                        }
                                    }
                                    else
                                        RESTfulResource.ThrowError(400, true, "invalid_argument", "Field '{0}' is not allowed in the '{1}' item.", p.Name, CollectionKey);
                                }
                                else
                                    RESTfulResource.ThrowError(400, true, "invalid_argument", "Unexpected field '{0}' is specified in the '{1}' item.", p.Name, CollectionKey);
                            }
                        else
                            RESTfulResource.ThrowError(400, true, "invalid_argument", "Only object items are allowed in the '{0}'.", CollectionKey);
                        if (itemKey.Count < PK.Count)
                            RESTfulResource.ThrowError(400, true, "invalid_argument", "Missing fields in the definition of an item in the '{0}'.", CollectionKey);
                        selectedValues.Add(string.Join(",", itemKey));
                    }
                }
            }
        }

        protected virtual void ValidateActionArguments(JObject payload, ActionArgs args)
        {
        }

        protected virtual void ExecuteFiles(PageRequest request, JObject payload, string commandName, string commandArgument)
        {
            if ((commandName == "Insert") || (commandName == "Update"))
            {
                var files = HttpContext.Current.Request.Files;
                foreach (string key in files.Keys)
                    if (!string.IsNullOrEmpty(key))
                    {
                        var f = files[key];
                        var blobFieldName = key;
                        if (!string.IsNullOrEmpty(PathField))
                        {
                            blobFieldName = PathField;
                            if (HttpMethod != "PUT")
                                RESTfulResource.ThrowError("invalid_method", "Method {0} is not allowed for the BLOB resource.", HttpMethod);
                        }
                        XPathNavigator blobField = null;
                        if (_fieldMap.TryGetValue(blobFieldName, out blobField))
                        {
                            var data = new byte[f.InputStream.Length];
                            f.InputStream.Read(data, 0, data.Length);
                            Blob.Write(blobField.GetAttribute("onDemandHandler", string.Empty), PrimaryKeyToPath(), f.FileName, f.ContentType, data);
                        }
                    }
            }
        }

        public virtual XPathNavigator FindAction(string action)
        {
            return FindAction(action, true);
        }

        public virtual XPathNavigator FindAction(string action, bool checkConstraints)
        {
            foreach (var match in EnumerateActions(action, 1, checkConstraints))
                return match.Value;
            return null;
        }

        public virtual SimpleConfigDictionary EnumerateActions(string action, int limit, bool checkConstraints)
        {
            var result = new SimpleConfigDictionary();
            var saveView = _view;
            if (string.IsNullOrEmpty(_view))
            {
                if (_isCollection)
                    _view = DefaultView("collection");
                else
                    _view = DefaultView("singleton");
            }
            action = action.Replace("-", string.Empty);
            var iterator = Config.Select("/c:dataController/c:actions/c:actionGroup/c:action");
            while (iterator.MoveNext())
            {
                var actionNav = iterator.Current;
                var id = actionNav.GetAttribute("id", string.Empty);
                var commandName = actionNav.GetAttribute("commandName", string.Empty);
                var isMatch = false;
                if (id.Equals(action, StringComparison.OrdinalIgnoreCase) || (((limit == 1) && commandName.Equals(action, StringComparison.OrdinalIgnoreCase)) || ((limit == -1) && (commandName.StartsWith(action, StringComparison.OrdinalIgnoreCase) && !Regex.IsMatch(id, "^a\\d+$")))))
                {
                    if (checkConstraints)
                    {
                        var whenView = actionNav.GetAttribute("whenView", string.Empty);
                        var whenKeySelected = actionNav.GetAttribute("whenKeySelected", string.Empty);
                        if (string.IsNullOrEmpty(whenView) || new Regex(whenView).IsMatch(_view))
                        {
                            if (string.IsNullOrEmpty(whenKeySelected) || (((whenKeySelected == "false") && _isCollection) || ((whenKeySelected == "true") && !_isCollection)))
                                isMatch = true;
                        }
                    }
                    else
                        isMatch = true;
                }
                if (isMatch)
                {
                    result[ToPathName(id)] = actionNav.Clone();
                    if (result.Count == limit)
                        break;
                }
            }
            _view = saveView;
            return result;
        }

        public string PrimaryKeyToPath()
        {
            var pkValues = new List<string>();
            foreach (var fvo in PK)
            {
                var v = fvo.Value;
                if (v != null)
                    pkValues.Add(v.ToString());
            }
            return string.Join("_", pkValues);
        }

        public string[] PrimaryKeyToFieldNames()
        {
            var pkFieldNames = new List<string>();
            foreach (var pkField in PK)
                pkFieldNames.Add(pkField.Name);
            return pkFieldNames.ToArray();
        }

        public void CreateOwnerCollectionLinks(JObject result)
        {
            var links = CreateLinks(result);
            if (links != null)
            {
                var startsWith = ControllerResource;
                if (!string.IsNullOrEmpty(_masterResource))
                    startsWith = _masterResource;
                var endsWith = startsWith;
                if (_lookupConfig != null)
                {
                    startsWith = _lookupResource;
                    endsWith = string.Empty;
                }
                else
                {
                    if (IsCollection)
                        endsWith = (endsWith + "?count=true");
                    else
                    {
                        startsWith = _id;
                        endsWith = string.Empty;
                    }
                }
                if (!string.IsNullOrEmpty(LastEntity))
                    AddLink("upLink", "GET", links, ReplaceRawUrlWith(startsWith, false, endsWith));
                if ((_lookupConfig == null) && ((_args["fields"] == null) && (_args[EmbedParam] == null)))
                    foreach (var viewId in EnumerateViews("collection", null))
                    {
                        var viewName = viewId;
                        var viewPath = viewId;
                        if (viewName == DefaultView("collection"))
                        {
                            viewName = string.Empty;
                            viewPath = string.Empty;
                        }
                        if (!string.IsNullOrEmpty(viewPath))
                            viewPath = ("/" + viewPath);
                        viewName = ToPathName(viewName);
                        viewPath = ToPathName(viewPath);
                        var entityPath = startsWith;
                        if (IsSingleton)
                            entityPath = string.Empty;
                        AddLink("collection", viewName, "GET", links, ReplaceRawUrlWith(startsWith, true, "{0}{1}?count=true", entityPath, viewPath));
                        AddLink("firstLink", viewName, "GET", links, ReplaceRawUrlWith(startsWith, true, "{0}{1}?page=0&limit={2}", entityPath, viewPath, PageSize));
                    }
            }
        }

        public virtual JObject RowToObject(List<DataField> fieldList, List<DataField> ignoreList, object[] row, List<int> pkIndexMap, List<int> fieldIndexMap)
        {
            var obj = new JObject();
            JProperty links = CreateLinks(obj);
            var pkAsString = PathKey;
            if (string.IsNullOrEmpty(pkAsString))
            {
                var pk = new List<string>();
                foreach (var pkFieldIndex in pkIndexMap)
                {
                    var v = row[fieldIndexMap[pkFieldIndex]];
                    if (v != null)
                        pk.Add(v.ToString());
                }
                pkAsString = string.Join("_", pk);
            }
            var selfLink = RawUrl;
            var requiresSingletonLinks = false;
            var isRootView = false;
            if (links != null)
            {
                if (!string.IsNullOrEmpty(pkAsString))
                {
                    if (string.IsNullOrEmpty(PathField))
                    {
                        // object resource
                        if (!string.IsNullOrEmpty(PathKey))
                        {
                            if (Action == null)
                            {
                                AddLink("selfLink", "GET", links, selfLink);
                                isRootView = IsTagged(_viewNav, "rest-api-root");
                                if (isRootView)
                                    foreach (var viewId in EnumerateViews("root", PathView))
                                    {
                                        var viewName = viewId;
                                        var viewPath = viewId;
                                        viewName = ToPathName(viewName);
                                        if (!string.IsNullOrEmpty(viewPath))
                                            viewPath = ("/" + ToPathName(viewPath));
                                        AddLink(ToApiName("selfLink"), viewName, "GET", links, ReplaceRawUrlWith(PathView, false, viewPath));
                                    }
                                else
                                {
                                    // singleton "self" links
                                    foreach (var viewId in EnumerateViews("singleton", PathView))
                                    {
                                        var viewName = viewId;
                                        var viewPath = viewId;
                                        if (viewId == DefaultView("singleton"))
                                        {
                                            viewName = "default";
                                            viewPath = string.Empty;
                                        }
                                        viewName = ToPathName(viewName);
                                        if (!string.IsNullOrEmpty(viewPath))
                                            viewPath = ("/" + ToPathName(viewPath));
                                        AddLink(ToApiName("selfLink"), viewName, "GET", links, ReplaceRawUrlWith(LastEntity, false, "{0}{1}", LastEntity, viewPath));
                                    }
                                    CreateOwnerCollectionLinks(obj);
                                }
                            }
                            requiresSingletonLinks = (Action == null);
                        }
                        else
                        {
                            // object is the item of a collection resource
                            selfLink = ExtendRawUrlWith(pkAsString);
                            AddLink("selfLink", "GET", links, selfLink);
                            foreach (var viewId in EnumerateViews("singleton", DefaultView("singleton")))
                                AddLink(ToApiName("selfLink"), ToPathName(viewId), "GET", links, ReplaceRawUrlWith(PathKey, false, "{0}/{1}", pkAsString, ToPathName(viewId)));
                        }
                    }
                    else
                    {
                        // object field resource
                        AddLink("selfLink", "GET", links, selfLink);
                        AddLink("upLink", "GET", links, ReplaceRawUrlWith(LastEntity, false, string.Empty));
                    }
                }
                else
                {
                    if (!string.IsNullOrEmpty(PathKey))
                        AddLink("collection", "GET", links, "/{0}", ControllerResource);
                }
            }
            var fieldIndex = 0;
            foreach (var df in fieldList)
                if (!ignoreList.Contains(df))
                {
                    if (_excludedFields.ContainsKey(df.Name))
                    {
                        fieldIndex++;
                        continue;
                    }
                    var addValueProperty = true;
                    var valuePropertyName = ToApiFieldName(df.Name);
                    var pathFieldName = ToPathName(df.Name);
                    if (!string.IsNullOrEmpty(PathField))
                        valuePropertyName = ToApiNameTemplate("valueKey", df.Name);
                    var v = row[fieldIndexMap[fieldIndex]];
                    if (df.Type == "DataView")
                    {
                        if (!AllowController(df.DataViewController))
                            continue;
                        // figure the default viewId for this DataView field
                        var viewId = df.DataViewId;
                        var otherCollectionViews = EnumerateViews(df.DataViewController, "collection", viewId);
                        var defaultViewId = DefaultView("collection", df.DataViewController);
                        if (viewId == defaultViewId)
                            viewId = string.Empty;
                        if (!string.IsNullOrEmpty(viewId))
                            viewId = ("/" + viewId);
                        // create the DataView field value and link
                        if (string.IsNullOrEmpty(PathField))
                        {
                            if (string.IsNullOrEmpty(PathKey))
                                v = EscapeLink(EnsurePublicApiKeyInUrl(ExtendRawUrlWith("{0}/{1}{2}", pkAsString, pathFieldName, viewId)));
                            else
                                v = EscapeLink(EnsurePublicApiKeyInUrl(ExtendRawUrlWith("{0}{1}", pathFieldName, viewId)));
                        }
                        else
                            addValueProperty = false;
                        if (links != null)
                        {
                            // create an embeddable link for the DataView field
                            ExtendLinkWith("embeddable", true, AddLink(df.Name, "GET", links, "{0}?count=true", Convert.ToString(v)));
                            ExtendLinkWith("embeddable", true, AddLink(df.Name, "firstLink", "GET", links, "{0}?page=0&limit={1}", Convert.ToString(v), PageSize));
                            // create embeddable links for other views in the DataView field controller
                            foreach (var fieldViewId in otherCollectionViews)
                            {
                                var viewName = fieldViewId;
                                var viewPath = fieldViewId;
                                if (fieldViewId == defaultViewId)
                                {
                                    viewName = "collection";
                                    viewPath = string.Empty;
                                }
                                else
                                    viewPath = ("/" + fieldViewId);
                                viewName = ToPathName(viewName);
                                viewPath = ToPathName(viewPath);
                                string fieldUrl;
                                if (string.IsNullOrEmpty(PathKey))
                                    fieldUrl = ExtendRawUrlWith("{0}/{1}{2}", pkAsString, pathFieldName, viewPath);
                                else
                                    fieldUrl = ExtendRawUrlWith("{0}{1}", pathFieldName, viewPath);
                                ExtendLinkWith("embeddable", true, AddLink(df.Name, viewName, "GET", links, "{0}", fieldUrl));
                                ExtendLinkWith("embeddable", true, AddLink(df.Name, (ToApiName("firstLink") + ("-" + viewName)), "GET", links, "{0}?page=0&limit={1}", fieldUrl, PageSize));
                            }
                        }
                    }
                    else
                    {
                        if (v != null)
                        {
                            if ((links != null) && (!string.IsNullOrEmpty(df.ItemsDataController) && (Action == null)))
                            {
                                if (AllowController(df.ItemsDataController))
                                {
                                    if (string.IsNullOrEmpty(PathKey))
                                        ExtendLinkWith("embeddable", true, AddLink(df.Name, "GET", links, ExtendRawUrlWith(false, "{0}/{1}", pkAsString, pathFieldName)));
                                    else
                                        ExtendLinkWith("embeddable", true, AddLink(df.Name, "GET", links, ExtendRawUrlWith(false, pathFieldName)));
                                    if (!string.IsNullOrEmpty(PathKey))
                                        CreateLookupLink(df, links);
                                }
                            }
                            else
                            {
                                if (df.OnDemand)
                                {
                                    if (v.ToString().StartsWith("null|"))
                                        v = null;
                                    else
                                    {
                                        if (string.IsNullOrEmpty(PathKey))
                                            v = ExtendRawUrlWith("{0}/{1}", pkAsString, pathFieldName);
                                        else
                                        {
                                            if (string.IsNullOrEmpty(PathField))
                                                v = ExtendRawUrlWith(pathFieldName);
                                            else
                                                v = ExtendRawUrlWith(string.Empty);
                                        }
                                        var qualifiedFileNameField = ToApiFieldName((df.Name + "FileName"));
                                        var defaultFileNameField = ToApiFieldName("FileName");
                                        var fileNameFieldIndex = 0;
                                        foreach (var f in fieldList)
                                        {
                                            var testFileName = ToApiFieldName(f.Name);
                                            if ((qualifiedFileNameField == testFileName) || (defaultFileNameField == testFileName))
                                            {
                                                var fileName = Convert.ToString(row[fieldIndexMap[fileNameFieldIndex]]);
                                                if (!string.IsNullOrEmpty(fileName))
                                                {
                                                    var extension = Path.GetExtension(fileName);
                                                    var blobPath = new List<string>(((string)(v)).Split('/'));
                                                    if (blobPath[(blobPath.Count - 1)] == LatestVersionLink)
                                                        blobPath.RemoveAt((blobPath.Count - 1));
                                                    var newFileName = (TextUtility.ToBase64UrlEncoded(Encoding.UTF8.GetBytes(string.Format("{0}/{1}/{2}", blobPath[(blobPath.Count - 2)], blobPath[(blobPath.Count - 1)], extension.Substring(1, 1)))) + extension);
                                                    blobPath.RemoveAt((blobPath.Count - 1));
                                                    blobPath.RemoveAt((blobPath.Count - 1));
                                                    if (RESTfulResource.LatestVersion == Controller)
                                                        blobPath.Add(LatestVersionLink);
                                                    blobPath.Add(newFileName);
                                                    v = string.Join("/", blobPath);
                                                }
                                                break;
                                            }
                                            fileNameFieldIndex++;
                                        }
                                        v = EnsurePublicApiKeyInUrl(((string)(v)));
                                    }
                                }
                            }
                        }
                        else
                        {
                            // the value of the field is "null"
                            if ((links != null) && !string.IsNullOrEmpty(df.ItemsDataController))
                            {
                                if (!string.IsNullOrEmpty(PathKey))
                                    CreateLookupLink(df, links);
                            }
                        }
                    }
                    if (((links != null) && !string.IsNullOrEmpty(df.ItemsDataController)) && (((df.ItemsDataController == ControllerName) && (PK.Count == 1)) && ((Action == null) && AllowController(df.ItemsDataController))))
                    {
                        var childrenPath = new List<string>();
                        if (string.IsNullOrEmpty(PathKey))
                            childrenPath.Add(pkAsString);
                        childrenPath.Add(ChildrenKey);
                        childrenPath.Add(pathFieldName);
                        ExtendLinkWith("embeddable", true, AddLink(ChildrenKey, ToApiFieldName(df.Name), "GET", links, ExtendRawUrlWith(false, string.Join("/", childrenPath))));
                    }
                    if (addValueProperty)
                        obj.Add(new JProperty(valuePropertyName, v));
                    fieldIndex++;
                }
            if (requiresSingletonLinks)
            {
                if (!isRootView)
                {
                    if (FindAction("Update") != null)
                    {
                        var allowEdit = AllowMethod(ControllerName, "PATCH");
                        if (allowEdit)
                            AddLink("editLink", "PATCH", links, ExtendRawUrlWith(string.Empty));
                        var allowReplace = AllowMethod(ControllerName, "PUT");
                        if (allowReplace)
                            AddLink("replaceLink", "PUT", links, ExtendRawUrlWith(string.Empty));
                        foreach (var df in fieldList)
                            if ((df.OnDemand && !df.ReadOnly) && (!df.IsVirtual && (allowEdit || allowReplace)))
                            {
                                AddLink("replaceLink", ToApiFieldName(df.Name), "PUT", links, ExtendRawUrlWith(ToPathName(df.Name)));
                                var blobValue = obj[ToApiFieldName(df.Name)];
                                if ((blobValue != null) && blobValue.Type != JTokenType.Null)
                                    AddLink("deleteLink", ToApiFieldName(df.Name), "DELETE", links, ExtendRawUrlWith(ToPathName(df.Name)));
                            }
                    }
                    if ((FindAction("Delete") != null) && ((_lookupConfig == null) && AllowMethod(ControllerName, "DELETE")))
                        AddLink("deleteLink", "DELETE", links, ExtendRawUrlWith(string.Empty));
                }
                EnumerateActions(links);
                CreateSchemaLink(links);
            }
            else
            {
                if ((Action != null) && IsSingleton)
                    AddLink("selfLink", "GET", links, ReplaceRawUrlWith(ActionPathName, false, string.Empty));
            }
            CreateLinks(obj);
            return obj;
        }

        public virtual JToken GetProperty(JObject obj, string propName, string propType)
        {
            var token = obj[propName];
            if (token != null)
                try
                {
                    TypeDescriptor.GetConverter(Type.GetType(("System." + propType))).ConvertFromString(Convert.ToString(token));
                }
                catch (Exception ex)
                {
                    RESTfulResource.ThrowError("invalid_parameter", "Parameter '{0}': {1}", propName, ex.Message);
                }
            return token;
        }

        public virtual void SetPropertyValue(JObject obj, string name, object value)
        {
            var propName = ToApiFieldName(name);
            if (value == null)
                obj[propName] = null;
            else
                obj[propName] = JToken.FromObject(value);
        }

        public virtual object GetPropertyValue(JObject obj, string propName, JObject schema)
        {
            var propSchema = schema[propName];
            var result = GetPropertyValue(obj, propName, ((string)(propSchema["type"])));
            if ((result == null) && (propSchema["default"] != null))
            {
                result = GetPropertyValue(((JObject)(schema[propName])), "default", ((string)(propSchema["type"])));
                if ((result is string) && ((string)(result)).StartsWith("$"))
                {
                    var namedValue = ((string)(result));
                    result = null;
                    var login = RESTfulResource.AuthorizationToLogin(null);
                    if (login != null)
                    {
                        if (namedValue == "$username")
                            result = login[0];
                        if (namedValue == "$password")
                            result = login[1];
                    }
                }
            }
            if (propSchema["values"] is JArray)
            {
                if ((result != null) && (Array.IndexOf(((JArray)(propSchema["values"])).ToObject<string[]>(), Convert.ToString(result)) == -1))
                    RESTfulResource.ThrowError(400, true, "invalid_argument", "Value '{0}' specified in '{1}' is invalid.", result, obj[propName].Path);
            }
            return result;
        }

        public virtual object GetPropertyValue(JObject obj, string propName, string propType)
        {
            object result = null;
            var token = obj[propName];
            if ((token != null) && token.Type != JTokenType.Null)
                try
                {
                    if (string.IsNullOrEmpty(propType))
                    {
                        propType = "String";
                        if (token.Type == JTokenType.Integer)
                            propType = "Int64";
                        else
                        {
                            if (token.Type == JTokenType.Float)
                                propType = "Double";
                            else
                            {
                                if (token.Type == JTokenType.Boolean)
                                    propType = "Boolean";
                                else
                                {
                                    if (token.Type == JTokenType.Date)
                                        propType = "DateTime";
                                    else
                                    {
                                        if (token.Type == JTokenType.Guid)
                                            result = Guid.Parse(Convert.ToString(token));
                                    }
                                }
                            }
                        }
                    }
                    if (result == null)
                        result = TypeDescriptor.GetConverter(Type.GetType(("System." + propType))).ConvertFromString(Convert.ToString(token));
                }
                catch (Exception ex)
                {
                    RESTfulResource.ThrowError(400, true, "invalid_argument", "Field '{0}': {1}", token.Path, ex.Message);
                }
            return result;
        }

        public void EnumerateActions(JProperty links)
        {
            if (IsCollection && (FindAction("Insert") != null))
            {
                var defaultCreateView = DefaultView("POST");
                foreach (var viewId in EnumerateViews("POST", null))
                {
                    var createView = ToPathName(viewId);
                    if (viewId == defaultCreateView)
                        createView = string.Empty;
                    if (AllowMethod(Controller, "POST"))
                        AddLink("createLink", createView, "POST", links, ExtendRawUrlWith(false, createView));
                }
            }
            foreach (var match in EnumerateActions("Custom", -1, true))
                if (AllowMethod(ControllerName, match.Key))
                    AddLink(match.Key, "POST", links, ExtendRawUrlWith(match.Key));
            foreach (var match in EnumerateActions("Report", -1, true))
                if (AllowMethod(ControllerName, match.Key))
                {
                    var reportMethod = "GET";
                    if (!string.IsNullOrEmpty(match.Value.GetAttribute("confirmation", string.Empty)))
                        reportMethod = "POST";
                    var allQueryParams = ToQueryParams(ReplaceRawUrlWith(string.Empty, true, match.Key));
                    var reportActionUrl = ExtendRawUrlWith(match.Key);
                    var queryParams = new StringBuilder("?");
                    string p = null;
                    if (allQueryParams.TryGetValue(FilterParam, out p))
                        queryParams.AppendFormat("{0}={1}", FilterParam, p);
                    if (allQueryParams.TryGetValue("sort", out p))
                    {
                        if (queryParams.Length > 1)
                            queryParams.Append("&");
                        queryParams.AppendFormat("{0}={1}", "sort", p);
                    }
                    if (queryParams.Length == 1)
                        queryParams.Clear();
                    AddLink(match.Key, reportMethod, links, (reportActionUrl + queryParams.ToString()));
                }
        }

        public void CreateSchemaLink(JProperty links)
        {
            if (!RequiresSchema && Hypermedia)
                AddLink("schemaLink", "GET", links, ExtendRawUrlWith(true, "?_schema=true"));
        }

        public void CreateUpLink(JProperty links)
        {
            var upUrl = ReplaceRawUrlWith(LastEntity, false, string.Empty);
            if (upUrl.EndsWith(("/" + ChildrenKey)))
                upUrl = upUrl.Substring(0, ((upUrl.Length - ChildrenKey.Length) - 1));
            AddLink("upLink", "GET", links, upUrl);
        }

        public void CreateLookupLink(DataField field, JProperty links)
        {
            if ((Action == null) && Convert.ToBoolean(ApplicationServicesBase.SettingsProperty("server.rest.hypermedia.links.lookups", true)))
            {
                var lookupFieldNames = new List<string>();
                // fetch "value" and "text" feilds
                if (!string.IsNullOrEmpty(field.ItemsDataValueField))
                    lookupFieldNames.Add(ToApiFieldName(field.ItemsDataValueField));
                if (!string.IsNullOrEmpty(field.ItemsDataTextField))
                    lookupFieldNames.Add(ToApiFieldName(field.ItemsDataTextField));
                // add "copy" fields
                if (!string.IsNullOrEmpty(field.Copy))
                    foreach (Match m in Regex.Matches(field.Copy, "(\\w+)\\s*=\\s*(\\w+)"))
                        lookupFieldNames.Add(ToApiFieldName(m.Groups[2].Value));
                var fieldsParam = string.Join(",", lookupFieldNames.ToArray());
                if (!string.IsNullOrEmpty(fieldsParam))
                    fieldsParam = ("&fields=" + fieldsParam);
                // figure the default lookup view
                var viewPath = field.ItemsDataView;
                if (!string.IsNullOrEmpty(viewPath) && viewPath != DefaultView("collection", field.ItemsDataController))
                    viewPath = ("/" + ToPathName(viewPath));
                ExtendLinkWith("embeddable", true, AddLink(("lookup-" + ToApiFieldName(field.Name)), "GET", links, "/{0}{1}?count=true{2}", ToPathName(field.ItemsDataController), viewPath, fieldsParam));
                if ((field.ItemsDataController == ControllerName) && (IsCollection && IsRoot))
                    ExtendLinkWith("embeddable", true, AddLink(RootKey, ToApiFieldName(field.Name), "GET", links, ExtendRawUrlWith("/root/{0}?count=true", ToPathName(field.Name))));
            }
        }

        protected virtual void EnumerateSchemaProperties(JObject schema, string inputKey, JObject target)
        {
            var source = FindSchemaInput(schema, inputKey, inputKey != "_input");
            if (source != null)
                foreach (var f in source.Properties())
                    if (f.Value.Type == JTokenType.Object)
                    {
                        var fieldSchema = new JObject();
                        var targetSchema = target;
                        if (inputKey.StartsWith("_") && inputKey != "_output")
                        {
                            var targetSchemaWrapper = ((JObject)(target[inputKey]));
                            if (targetSchemaWrapper == null)
                            {
                                targetSchemaWrapper = new JObject();
                                var p = new JProperty(inputKey, targetSchemaWrapper);
                                if ((inputKey == "_parameters") || (inputKey == "_path"))
                                    target.AddFirst(p);
                                else
                                    target.Add(p);
                            }
                            targetSchema = ((JObject)(targetSchemaWrapper[SchemaKey]));
                            if (targetSchema == null)
                            {
                                targetSchema = new JObject();
                                targetSchemaWrapper.Add(new JProperty(SchemaKey, targetSchema));
                            }
                        }
                        targetSchema.Add(new JProperty(f.Name, fieldSchema));
                        if (f.Value["properties"] != null)
                        {
                            var hint = f.Value["hint"];
                            if (hint != null)
                                fieldSchema.Add(new JProperty("hint", hint));
                            if (Convert.ToBoolean(f.Value["required"]))
                                fieldSchema.Add(new JProperty("required", true));
                            if (Convert.ToBoolean(f.Value["array"]))
                                fieldSchema.Add(new JProperty("array", true));
                            var complexFieldSchema = new JObject();
                            fieldSchema.Add(new JProperty(SchemaKey, complexFieldSchema));
                            EnumerateSchemaProperties(((JObject)(f.Value)), "properties", complexFieldSchema);
                        }
                        else
                            foreach (var p in ((JObject)(f.Value)).Properties())
                                if (Regex.IsMatch(p.Name, "type|length|default|required|key|readOnly|lookup|child|blob|label|footer|hint|values|literal"))
                                    fieldSchema.Add(new JProperty(p.Name, p.Value));
                    }
        }

        public virtual void AddSchema(JObject result)
        {
            if ((result != null) && (result["error"] != null))
            {
                if (!AllowsSchema)
                    ((JObject)(((JArray)(result["error"]["errors"])).First)).Add(new JProperty("hint", "Set 'server.rest.schema.enabled' to true in the settings to get more information about this resource."));
            }
            if ((!RequiresSchema || !AllowsSchema) || (result == null))
                return;
            var schema = new JObject();
            var schemaProp = new JProperty(SchemaKey, schema);
            if (result["error"] == null)
                result.AddFirst(schemaProp);
            else
                result.Add(schemaProp);
            EmbedCustomSchema(CustomSchema, schema);
            if (Config == null)
                return;
            var fieldList = ToSchemaFields(ControllerName, PathView);
            var inputSchema = ((JObject)(schema.SelectToken("_input._schema")));
            if (inputSchema != null)
            {
                // create a '*' key indicating that the output keys fields are also accepted in the input
                if (!inputSchema.ContainsKey("*"))
                    inputSchema.Add(new JProperty("*", true));
            }
            // add the fields
            AddFieldsToSchema(schema, fieldList);
        }

        protected virtual void EmbedCustomSchema(JObject schema, JObject target)
        {
            JObject inputSchema = null;
            if (HttpMethod != "GET")
            {
                var input = ((JObject)(target["_input"]));
                if ((input == null) && (FindSchemaInput(schema, "_input", false) != null))
                {
                    input = new JObject();
                    target.Add(new JProperty("_input", input));
                }
                if (input != null)
                {
                    inputSchema = ((JObject)(input[SchemaKey]));
                    if (inputSchema == null)
                    {
                        inputSchema = new JObject();
                        input.Add(new JProperty(SchemaKey, inputSchema));
                    }
                }
            }
            if (schema != null)
            {
                EnumerateSchemaProperties(schema, "_parameters", target);
                EnumerateSchemaProperties(schema, "_path", target);
                EnumerateSchemaProperties(schema, "_input", target);
                EnumerateSchemaProperties(schema, "_output", target);
                var hint = Convert.ToString(schema["hint"]).Trim();
                if (!string.IsNullOrEmpty(hint))
                {
                    var outputElements = new List<JProperty>();
                    foreach (var p in target.Properties())
                        if (!p.Name.StartsWith("_"))
                            outputElements.Add(p);
                    target.AddFirst(new JProperty("hint", hint));
                    if (outputElements.Count > 0)
                    {
                        var output = new JObject();
                        target.Add(new JProperty("_output", output));
                        foreach (var p in outputElements)
                        {
                            output.Add(p);
                            target.Remove(p.Name);
                        }
                    }
                }
            }
        }

        public JObject FindSchemaInput(JObject schema, string inputKey, bool resolve)
        {
            JObject inputSchema = null;
            if (schema != null)
            {
                var inputSchemaValue = schema[inputKey];
                if (inputSchemaValue != null)
                {
                    if (inputSchemaValue.Type == JTokenType.String)
                    {
                        if (resolve)
                            inputSchema = ((JObject)(schema.Parent.Parent.SelectToken(Convert.ToString(inputSchemaValue))));
                    }
                    else
                        inputSchema = ((JObject)(inputSchemaValue));
                }
            }
            return inputSchema;
        }

        protected virtual void ValidateWithSchema(JObject schema, string inputKey, JObject payload, string propPath)
        {
            var request = HttpContext.Current.Request;
            if (!string.IsNullOrEmpty(propPath))
                propPath = (propPath + ".");
            var errors = new List<RESTfulResourceException>();
            JObject inputSchema = FindSchemaInput(schema, inputKey, true);
            if (inputSchema == null)
            {
                if (inputKey == "_parameters")
                    foreach (var paramName in request.QueryString)
                        try
                        {
                            if ((Array.IndexOf(new string[] {
                                        LinksKey,
                                        SchemaKey,
                                        EmbedParam,
                                        "api_key",
                                        "x-api-key"}, paramName) == -1) && (!IsCollection || (Array.IndexOf(new string[] {
                                                    FilterParam,
                                                    "sort"}, paramName) == -1)))
                                RESTfulResource.ThrowError(400, true, "invalid_parameter", "Unexpected parameter '{0}' is specified in the URL.", paramName);
                        }
                        catch (RESTfulResourceException ex)
                        {
                            errors.Add(ex);
                        }
                if (errors.Count > 0)
                    throw new RESTfulResourceException(errors);
                return;
            }
            var inputIsBody = ((inputKey == "_input") || !inputKey.StartsWith("_"));
            var nameType = "field";
            var nameSource = "body";
            var errorType = "invalid_argument";
            var propNames = new List<string>();
            if (inputIsBody)
                foreach (var p in payload.Properties())
                    propNames.Add(p.Name);
            if (inputKey == "_path")
            {
                nameType = "resource";
                nameSource = "path";
                errorType = "invalid_path";
                foreach (var p in inputSchema.Properties())
                {
                    if (Convert.ToBoolean(p.Value["literal"]))
                        payload[p.Name] = p.Name;
                    else
                    {
                        if (_customSchemaPath != null)
                            payload[p.Name] = _customSchemaPath[p.Name].Value;
                    }
                    propNames.Add(p.Name);
                }
            }
            if (inputKey == "_parameters")
            {
                nameType = "parameter";
                nameSource = "URL";
                errorType = "invalid_parameter";
                foreach (string paramName in request.QueryString)
                    if (!string.IsNullOrEmpty(paramName))
                    {
                        payload[paramName] = request.QueryString[paramName].Trim();
                        propNames.Add(paramName);
                    }
            }
            foreach (var propName in propNames)
                try
                {
                    if (inputSchema[propName] == null)
                    {
                        if (Array.IndexOf(new string[] {
                                    LinksKey,
                                    SchemaKey,
                                    EmbeddedKey}, propName) == -1)
                        {
                            if (!inputIsBody || (((schema.SelectToken(("_path." + propName)) == null) && (schema.SelectToken(("_parameters." + propName)) == null)) && ((inputSchema["*"] == null) || !FieldMap.ContainsKey(propName))))
                                RESTfulResource.ThrowError(400, true, errorType, "Unexpected {0} '{1}' is specified in the {2}.", nameType, (propPath + propName), nameSource);
                        }
                        else
                            payload.Remove(propName);
                    }
                }
                catch (RESTfulResourceException ex)
                {
                    errors.Add(ex);
                }
            foreach (var p in inputSchema.Properties())
                try
                {
                    var v = payload[p.Name];
                    if (((v == null) && (HttpMethod == "PATCH")) || ((p.Name == "*") || ((p.Name == CollectionKey) && IsCollection)))
                        continue;
                    if (p.Value["properties"] != null)
                    {
                        if (v != null)
                        {
                            if (v.Type == JTokenType.Object)
                                ValidateWithSchema(((JObject)(inputSchema[p.Name])), "properties", ((JObject)(payload[p.Name])), (propPath + p.Name));
                            else
                                RESTfulResource.ThrowError(400, true, errorType, "Object is expected as the value of the field '{0}' in the {1}.", (propPath + p.Name), nameSource);
                        }
                        else
                        {
                            if (Convert.ToBoolean(p.Value["required"]))
                                RESTfulResource.ThrowError(400, true, errorType, "{0} '{1}' is expected in the {2}.", (nameType.Substring(0, 1).ToUpper() + nameType.Substring(1)), (propPath + p.Name), nameSource);
                        }
                    }
                    else
                    {
                        var propValue = GetPropertyValue(payload, p.Name, inputSchema);
                        if ((v == null) && (propValue != null))
                        {
                            SetPropertyValue(payload, p.Name, propValue);
                            v = payload[p.Name];
                        }
                        if (Convert.ToBoolean(p.Value["required"]))
                        {
                            if (v == null)
                                RESTfulResource.ThrowError(400, true, errorType, "{0} '{1}' is expected in the {2}.", (nameType.Substring(0, 1).ToUpper() + nameType.Substring(1)), (propPath + p.Name), nameSource);
                            if (v.Type == JTokenType.Null)
                                RESTfulResource.ThrowError(400, true, errorType, "{0} '{1}' is expected in the {2}. The 'null' value is specified.", (nameType.Substring(0, 1).ToUpper() + nameType.Substring(1)), (propPath + p.Name), nameSource);
                            if ((v.Type == JTokenType.String) && string.IsNullOrEmpty(((string)(v))))
                                RESTfulResource.ThrowError(400, true, errorType, "Non-blank {0} '{1}' is expected in the {2}.", nameType, (propPath + p.Name), nameSource);
                        }
                        if (propValue is string)
                        {
                            var len = Convert.ToString(inputSchema[p.Name]["length"]);
                            if (!string.IsNullOrEmpty(len) && (Convert.ToInt32(len) < ((string)(propValue)).Length))
                                RESTfulResource.ThrowError("invalid_argument", "The maximum length of the field '{0}' is {1}.", p.Name, len);
                        }
                        SetPropertyValue(payload, p.Name, propValue);
                    }
                }
                catch (RESTfulResourceException ex)
                {
                    errors.Add(ex);
                    foreach (var related in ex.Related)
                        errors.Add(related);
                }
            if (errors.Count > 0)
                throw new RESTfulResourceException(errors);
        }

        protected virtual void MergePayloads(JObject source, JObject dest)
        {
            foreach (var p in source.Properties())
            {
                var destVal = dest[p.Name];
                if ((destVal != null) && Convert.ToString(destVal) != Convert.ToString(p.Value))
                    RESTfulResource.ThrowError(403, "invalid_argument", "Field '{0}' must be set to '{1}' in the body.", p.Name, p.Value);
                dest[p.Name] = p.Value;
            }
        }

        public virtual bool ExecuteWithSchema(JObject schema, JObject payload, JObject result)
        {
            var handled = false;
            if (schema != null)
            {
                if (!RESTfulResource.IsAuthorized(schema))
                    RESTfulResource.ThrowError(403, "unauthorized", "Insufficient credentials to access this resource.");
                var pathPayload = new JObject();
                ValidateWithSchema(schema, "_path", pathPayload, string.Empty);
                var parametersPayload = new JObject();
                ValidateWithSchema(schema, "_parameters", parametersPayload, string.Empty);
                ValidateWithSchema(schema, "_input", payload, string.Empty);
                MergePayloads(pathPayload, payload);
                MergePayloads(parametersPayload, payload);
            }
            if (!string.IsNullOrEmpty(OAuth))
            {
                handled = true;
                // execute the method of oatuh2/v2 endpoint
                ExecuteOAuth(schema, payload, result);
                if (HttpMethod != "GET")
                    HttpContext.Current.Response.Cache.SetNoStore();
            }
            return handled;
        }

        public virtual bool AllowMethod(string controller, string method)
        {
            if (string.IsNullOrEmpty(controller))
                return true;
            if (!AllowController(controller))
                return false;
            if (LastAclRole == null)
                return true;
            if (string.IsNullOrEmpty(method))
            {
                method = ActionPathName;
                if (string.IsNullOrEmpty(method))
                    method = HttpMethod;
            }
            var role = LastAclRole;
            while (role != null)
            {
                Regex re = null;
                try
                {
                    re = new Regex(Convert.ToString(role.Value), RegexOptions.IgnoreCase);
                }
                catch (Exception ex)
                {
                    RESTfulResource.ThrowError(500, "invalid_config", "\"Rule \'server.rest.acl.\\\"{0}\\\".\\\"{1}\\\".\\\"{2}\\\"\' specified in touch-settings.json is not a valid regular expression. Error: {3}", ((JProperty)(role.Parent.Parent)).Name, role.Name, role.Value, ex.Message);
                }
                if (re.IsMatch(method))
                    return true;
                role = ((JProperty)(role.Next));
                while ((role != null) && !((UserScopes.Contains(role.Name) || HttpContext.Current.User.IsInRole(role.Name))))
                    role = ((JProperty)(role.Next));
            }
            return false;
        }

        public string TrimLocationToIdentifier()
        {
            var path = Location;
            if (string.IsNullOrEmpty(Id))
                return path;
            var index = path.LastIndexOf(("/" + Id));
            if (index == -1)
                return path;
            return path.Substring(0, ((index + Id.Length) + 1));
        }
    }
}
