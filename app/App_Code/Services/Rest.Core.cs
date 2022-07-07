using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web;
using System.Web.Caching;
using System.Web.Security;
using System.Xml.XPath;
using Newtonsoft.Json.Linq;
using MyCompany.Data;
using MyCompany.Handlers;

namespace MyCompany.Services.Rest
{
    public class SimpleConfigDictionary : SortedDictionary<string, XPathNavigator>
    {
    }

    public class ConfigDictionary : SimpleConfigDictionary
    {

        public new XPathNavigator this[string key]
        {
            get
            {
                return base[NormalizeKey(key)];
            }
            set
            {
                base[NormalizeKey(key)] = value;
            }
        }

        public new bool ContainsKey(string key)
        {
            return base.ContainsKey(NormalizeKey(key));
        }

        public new bool TryGetValue(string key, out XPathNavigator value)
        {
            return base.TryGetValue(NormalizeKey(key), out value);
        }

        public new void Add(string key, XPathNavigator value)
        {
            base.Add(NormalizeKey(key), value);
        }

        public static string NormalizeKey(string key)
        {
            return key.ToLower().Replace("-", string.Empty).Replace("_", string.Empty);
        }
    }

    public class RESTfulResourceConfiguration
    {

        private string _controllerResource;

        private string _controllerName;

        public static int AccessTokenSize = 80;

        public static int RefreshTokenSize = 64;

        public static int AuthorizationRequestLifespan = 15;

        public static int AuthorizationCodeLifespan = 2;

        public static int MaximumPictureLifespan = (24 * 60);

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private bool _replaceEmbedded;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private bool _removeLinks;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _outputContentType;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _pathView;

        private string _pathAction;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _pathKey;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _lastEntity;

        private string _pathField;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private bool _hypermedia;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _outputStyle;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _linkStyle;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private bool _linkMethod;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _linksPosition;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private bool _allowsSchema;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private bool _requiresSchema;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private bool _requiresData;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _embedParam;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _filterParam;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _linksKey;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _schemaKey;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _embeddedKey;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _embeddableKey;

        private string _xmlRoot;

        private string _xmlItem;

        private string _collectionKey;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _parametersKey;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _childrenKey;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _rootKey;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _latestVersionLink;

        private ControllerConfiguration _config;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _rawUrl;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _httpMethod;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private Dictionary<string, object> _parameters;

        private SortedDictionary<string, ControllerConfiguration> _configList;

        private SortedDictionary<string, string> _names;

        private int _limit;

        private int _pageSize;

        private Regex _endpointValidator;

        private JProperty _lastAclRole;

        private List<string> _userScopes;

        public RESTfulResourceConfiguration()
        {
            var request = HttpContext.Current.Request;
            HttpMethod = request.HttpMethod;
            RawUrl = request.RawUrl;
            _configList = new SortedDictionary<string, ControllerConfiguration>();
            LinkStyle = Convert.ToString(ApplicationServicesBase.SettingsProperty("server.rest.hypermedia.links.style", "object"));
            LinkMethod = Convert.ToBoolean(ApplicationServicesBase.SettingsProperty("server.rest.hypermedia.links.method", false));
            LinksPosition = Convert.ToString(ApplicationServicesBase.SettingsProperty("server.rest.hypermedia.links.position", "first"));
            OutputStyle = Convert.ToString(ApplicationServicesBase.SettingsProperty("server.rest.output.style", "camelCase"));
            ReplaceEmbedded = (Convert.ToBoolean(ApplicationServicesBase.SettingsProperty("server.rest.hypermedia.embedded.replace", false)) || (request.Headers["X-Restful-HypermediaEmbeddedReplace"] == "true"));
            OutputContentType = request.Headers["X-Restful-OutputContentType"];
            // init the output key map for parameters that are not named after the logical names, e.g firstLink=first
            _names = new SortedDictionary<string, string>();
            _names["embeddable"] = "embeddable";
            _names["embedParam"] = "_embed";
            _names["_embedded"] = "_embedded";
            _names["selfLink"] = "self";
            _names["latestVersionLink"] = "latest-version";
            _names["upLink"] = "up";
            _names["firstLink"] = "first";
            _names["prevLink"] = "prev";
            _names["nextLink"] = "next";
            _names["lastLink"] = "last";
            _names["filterParam"] = "filter";
            _names["newLink"] = "newLink";
            _names["createLink"] = "create";
            _names["editLink"] = "edit";
            _names["replaceLink"] = "replace";
            _names["deleteLink"] = "delete";
            _names["schemaLink"] = "schema";
            _names["xmlItem"] = "item";
            _names["xmlRoot"] = "data";
            _names["valueKey"] = "value";
            _names["childrenKey"] = "children";
            _names["rootKey"] = "root";
            _names["resultKey"] = "result";
            _names["resultSetKey"] = "collection";
            var halKeys = ApplicationServicesBase.SettingsProperty("server.rest.output.names");
            if (halKeys is JObject)
                foreach (var p in ((JObject)(halKeys)))
                    _names[p.Key] = Convert.ToString(p.Value);
            _linksKey = ToApiName("_links");
            _embeddedKey = ToApiName("_embedded");
            _embeddableKey = ToApiName("embeddable");
            _schemaKey = ToApiName("_schema");
            _embedParam = ToApiName("embedParam");
            _filterParam = ToApiName("filterParam");
            _childrenKey = ToApiName("childrenKey");
            _rootKey = ToApiName("rootKey");
            _latestVersionLink = ToApiName("latestVersionLink");
            var schemaParameter = request.QueryString[SchemaKey];
            if (string.IsNullOrEmpty(schemaParameter))
                schemaParameter = request.Headers["X-Restful-Schema"];
            AllowsSchema = Convert.ToBoolean(ApplicationServicesBase.SettingsProperty("server.rest.schema.enabled", true));
            RequiresSchema = (((schemaParameter == "true") || (schemaParameter == "only")) && AllowsSchema);
            RequiresData = schemaParameter != "only";
            RemoveLinks = (((request.QueryString[LinksKey] == "false") || (request.Headers["X-Restful-Hypermedia"] == "false")) || !Convert.ToBoolean(ApplicationServicesBase.SettingsProperty("server.rest.output.links", true)));
            Hypermedia = Convert.ToBoolean(ApplicationServicesBase.SettingsProperty("server.rest.hypermedia.enabled", true));
            if (RemoveLinks && Hypermedia)
                ReplaceEmbedded = true;
            _parameters = new Dictionary<string, object>();
            _parametersKey = "parameters";
            var endpoint = ((string)(ApplicationServicesBase.SettingsProperty("server.rest.endpoint")));
            if (!string.IsNullOrEmpty(endpoint))
                _endpointValidator = new Regex(endpoint, RegexOptions.IgnoreCase);
        }

        public ApplicationServices App
        {
            get
            {
                return ApplicationServicesBase.Current;
            }
        }

        public bool ReplaceEmbedded
        {
            get
            {
                return _replaceEmbedded;
            }
            set
            {
                _replaceEmbedded = value;
            }
        }

        public bool RemoveLinks
        {
            get
            {
                return _removeLinks;
            }
            set
            {
                _removeLinks = value;
            }
        }

        public string OutputContentType
        {
            get
            {
                return _outputContentType;
            }
            set
            {
                _outputContentType = value;
            }
        }

        public virtual string ControllerName
        {
            get
            {
                return _controllerName;
            }
            set
            {
                _controllerName = value;
                if (string.IsNullOrEmpty(_controllerName))
                    _controllerResource = null;
                else
                {
                    _controllerResource = ToPathName(value);
                    _limit = Convert.ToInt32(ApplicationServicesBase.SettingsProperty("server.rest.output.limit.default", 100));
                    _pageSize = Convert.ToInt32(ApplicationServicesBase.SettingsProperty("server.rest.output.pageSize.default", 10));
                    _limit = Convert.ToInt32(ApplicationServicesBase.SettingsProperty(("server.rest.output.limit." + ControllerResource), _limit));
                    _pageSize = Convert.ToInt32(ApplicationServicesBase.SettingsProperty(("server.rest.output.pageSize." + ControllerResource), _pageSize));
                }
            }
        }

        public virtual string ControllerResource
        {
            get
            {
                return _controllerResource;
            }
        }

        public string PathView
        {
            get
            {
                return _pathView;
            }
            set
            {
                _pathView = value;
            }
        }

        public string PathAction
        {
            get
            {
                return _pathAction;
            }
            set
            {
                _pathAction = value;
                _pathField = null;
            }
        }

        public string PathCollectionView
        {
            get
            {
                var result = PathView;
                if (string.IsNullOrEmpty(result) || (result == DefaultView("collection")))
                    return string.Empty;
                return ("/" + ToPathName(result));
            }
        }

        public string PathObjectView
        {
            get
            {
                var result = PathView;
                if (result == DefaultView("singleton"))
                    return string.Empty;
                return ("/" + result);
            }
        }

        public string PathKey
        {
            get
            {
                return _pathKey;
            }
            set
            {
                _pathKey = value;
            }
        }

        public string LastEntity
        {
            get
            {
                return _lastEntity;
            }
            set
            {
                _lastEntity = value;
            }
        }

        public string PathField
        {
            get
            {
                return _pathField;
            }
            set
            {
                _pathField = ToApiFieldName(value);
            }
        }

        public bool Hypermedia
        {
            get
            {
                return _hypermedia;
            }
            set
            {
                _hypermedia = value;
            }
        }

        public string OutputStyle
        {
            get
            {
                return _outputStyle;
            }
            set
            {
                _outputStyle = value;
            }
        }

        public string LinkStyle
        {
            get
            {
                return _linkStyle;
            }
            set
            {
                _linkStyle = value;
            }
        }

        public bool LinkMethod
        {
            get
            {
                return _linkMethod;
            }
            set
            {
                _linkMethod = value;
            }
        }

        public string LinksPosition
        {
            get
            {
                return _linksPosition;
            }
            set
            {
                _linksPosition = value;
            }
        }

        public bool AllowsSchema
        {
            get
            {
                return _allowsSchema;
            }
            set
            {
                _allowsSchema = value;
            }
        }

        public bool RequiresSchema
        {
            get
            {
                return _requiresSchema;
            }
            set
            {
                _requiresSchema = value;
            }
        }

        public bool RequiresSchemaOnly
        {
            get
            {
                return (HttpMethod != "GET" && (RequiresSchema && !RequiresData));
            }
        }

        public bool RequiresData
        {
            get
            {
                return _requiresData;
            }
            set
            {
                _requiresData = value;
            }
        }

        public string EmbedParam
        {
            get
            {
                return _embedParam;
            }
            set
            {
                _embedParam = value;
            }
        }

        public string FilterParam
        {
            get
            {
                return _filterParam;
            }
            set
            {
                _filterParam = value;
            }
        }

        public string LinksKey
        {
            get
            {
                return _linksKey;
            }
            set
            {
                _linksKey = value;
            }
        }

        public string SchemaKey
        {
            get
            {
                return _schemaKey;
            }
            set
            {
                _schemaKey = value;
            }
        }

        public string EmbeddedKey
        {
            get
            {
                return _embeddedKey;
            }
            set
            {
                _embeddedKey = value;
            }
        }

        public string EmbeddableKey
        {
            get
            {
                return _embeddableKey;
            }
            set
            {
                _embeddableKey = value;
            }
        }

        public string XmlRoot
        {
            get
            {
                if (string.IsNullOrEmpty(_xmlRoot))
                    _xmlRoot = ToApiNameTemplate("xmlRoot", ControllerName);
                return _xmlRoot;
            }
        }

        public string XmlItem
        {
            get
            {
                if (string.IsNullOrEmpty(_xmlItem) && !string.IsNullOrEmpty(XmlRoot))
                    _xmlItem = ToApiNameTemplate("xmlItem", ControllerName);
                return _xmlItem;
            }
        }

        public string CollectionKey
        {
            get
            {
                if (string.IsNullOrEmpty(_collectionKey))
                    _collectionKey = ToApiNameTemplate("collection", ControllerName);
                return _collectionKey;
            }
        }

        public string ParametersKey
        {
            get
            {
                return _parametersKey;
            }
            set
            {
                _parametersKey = value;
            }
        }

        public string ChildrenKey
        {
            get
            {
                return _childrenKey;
            }
            set
            {
                _childrenKey = value;
            }
        }

        public string RootKey
        {
            get
            {
                return _rootKey;
            }
            set
            {
                _rootKey = value;
            }
        }

        public string LatestVersionLink
        {
            get
            {
                return _latestVersionLink;
            }
            set
            {
                _latestVersionLink = value;
            }
        }

        public ControllerConfiguration Config
        {
            get
            {
                return _config;
            }
            set
            {
                _config = value;
                ControllerName = _config.ControllerName;
            }
        }

        public string RawUrl
        {
            get
            {
                return _rawUrl;
            }
            set
            {
                _rawUrl = value;
            }
        }

        public string HttpMethod
        {
            get
            {
                return _httpMethod;
            }
            set
            {
                _httpMethod = value;
            }
        }

        public bool IsImmutable
        {
            get
            {
                return (HttpMethod == "GET");
            }
        }

        public Dictionary<string, object> Parameters
        {
            get
            {
                return _parameters;
            }
            set
            {
                _parameters = value;
            }
        }

        public int Limit
        {
            get
            {
                return _limit;
            }
        }

        public int PageSize
        {
            get
            {
                return _pageSize;
            }
        }

        public virtual int IdTokenDuration
        {
            get
            {
                return Convert.ToInt32(ApplicationServices.SettingsProperty("server.rest.authorization.oauth2.idTokenDuration", App.GetAccessTokenDuration("server.rest.authorization.oauth2.accessTokenDuration")));
            }
        }

        public virtual int PictureLifespan
        {
            get
            {
                return Math.Max(MaximumPictureLifespan, IdTokenDuration);
            }
        }

        public Regex EndpointValidator
        {
            get
            {
                return _endpointValidator;
            }
        }

        public JProperty LastAclRole
        {
            get
            {
                return _lastAclRole;
            }
        }

        public virtual JObject IdClaims
        {
            get
            {
                return null;
            }
        }

        public virtual List<string> UserScopes
        {
            get
            {
                if (_userScopes == null)
                    _userScopes = RESTfulResource.Scopes;
                return _userScopes;
            }
        }

        public virtual string ToPathName(string name)
        {
            return Regex.Replace(name, "(\\p{Ll})(\\p{Lu})", "$1-$2").ToLower();
        }

        public virtual string ToApiName(string baseName, string name)
        {
            name = ToApiName(name);
            return (ToPathName(baseName) + ("-" + ToApiName(name)));
        }

        public virtual string ToApiName(string name)
        {
            var newName = string.Empty;
            if (_names.TryGetValue(name, out newName))
                name = newName;
            return name;
        }

        public virtual string ToApiFieldName(string name)
        {
            if (OutputStyle == "CamelCase")
                return name;
            name = Regex.Replace(name, "^(ID|PK|FK)", ReplaceIdWithLowerAndLower);
            name = Regex.Replace(name, "(\\p{Ll})(ID|PK|FK|NO)", ReplaceIdWithUpperAndLower);
            if (OutputStyle == "snake")
                name = Regex.Replace(name, "(\\p{Ll})(\\p{Lu})", "$1_$2").ToLower();
            else
            {
                if (OutputStyle == "lowercase")
                    name = name.ToLower();
                else
                    name = Regex.Replace(name, "^((\\p{Lu})(\\p{Ll}+))(\\p{Lu}|$)", ReplaceIdWithLeadingLower);
            }
            return name;
        }

        public virtual string ToApiNameTemplate(string template, string replaceWith)
        {
            template = ToApiName(template);
            template = template.Replace("{name}", replaceWith);
            return ToApiFieldName(template);
        }

        private static string ReplaceIdWithUpperAndLower(Match m)
        {
            var id = m.Groups[2].Value;
            return (m.Groups[1].Value + (id.Substring(0, 1) + id.Substring(1).ToLower()));
        }

        private static string ReplaceIdWithLowerAndLower(Match m)
        {
            return m.Groups[1].Value.ToLower();
        }

        private static string ReplaceIdWithLeadingLower(Match m)
        {
            return (m.Groups[1].Value.ToLower() + m.Groups[4].Value);
        }

        public virtual string ToDataFieldName(string name)
        {
            return Regex.Replace(name, "(_|^)(.)", ReplaceWithUpper);
        }

        private static string ReplaceWithUpper(Match m)
        {
            return m.Groups[2].Value.ToUpper();
        }

        public Dictionary<string, DataField> ToFieldDictionary(string controllerName, string view)
        {
            var r = new PageRequest()
            {
                Controller = controllerName,
                View = view,
                RequiresMetaData = true,
                DoesNotRequireData = true,
                DoesNotRequireAggregates = true
            };
            var p = ControllerFactory.CreateDataController().GetPage(r.Controller, r.View, r);
            var dictionary = new Dictionary<string, DataField>();
            var apiNone = new List<DataField>();
            foreach (var field in p.Fields)
                if (field.IsTagged("rest-api-none"))
                    apiNone.Add(field);
            foreach (var field in p.Fields)
                if (!apiNone.Contains(field))
                    dictionary[field.Name] = field;
            return dictionary;
        }

        public List<DataField> ToSchemaFields(string controllerName, string view)
        {
            var dictionary = ToFieldDictionary(controllerName, view);
            var fieldList = new List<DataField>();
            foreach (var fieldDef in dictionary)
                if (fieldDef.Value.IsPrimaryKey)
                    fieldList.Add(fieldDef.Value);
            foreach (var fieldDef in dictionary)
                if (!fieldList.Contains(fieldDef.Value))
                {
                    fieldList.Add(fieldDef.Value);
                    var aliasFieldName = fieldDef.Value.AliasName;
                    if (!string.IsNullOrEmpty(aliasFieldName) && dictionary.ContainsKey(aliasFieldName))
                    {
                        var aliasField = dictionary[aliasFieldName];
                        if (!fieldList.Contains(aliasField))
                            fieldList.Add(aliasField);
                    }
                }
            return fieldList;
        }

        public void AddFieldsToSchema(JObject schema, List<DataField> fieldList)
        {
            foreach (var field in fieldList)
            {
                var f = new JObject();
                f["type"] = field.Type;
                if (field.Len > 0)
                    f["length"] = field.Len;
                if (field.HasDefaultValue)
                    f["default"] = field.DefaultValue;
                if (!field.AllowNulls)
                    f["required"] = true;
                if (field.IsPrimaryKey)
                    f["key"] = true;
                if (field.ReadOnly)
                    f["readOnly"] = true;
                var headerText = field.HeaderText;
                if (string.IsNullOrEmpty(headerText))
                    headerText = field.Label;
                if (!string.IsNullOrEmpty(field.ItemsDataController))
                    f["lookup"] = true;
                if (field.ItemsDataController == ControllerName)
                    f["child"] = true;
                if (field.OnDemand)
                    f["blob"] = true;
                f["label"] = headerText;
                var watermark = field.Watermark;
                if (!string.IsNullOrEmpty(watermark))
                    f["hint"] = watermark;
                var footerText = field.FooterText;
                if (!string.IsNullOrEmpty(footerText))
                    f["footer"] = footerText;
                schema.Add(new JProperty(ToApiFieldName(field.Name), f));
            }
        }

        public void ExtendLinkWith(string key, bool value, JToken link)
        {
            if (link != null)
            {
                if (link is JProperty)
                    link = ((JProperty)(link)).Value;
                if (!((link is JValue)))
                    link[ToApiName(key)] = value;
            }
        }

        public string DefaultView(string type)
        {
            return DefaultView(type, _controllerName);
        }

        public virtual string DefaultView(string type, string controller)
        {
            type = type.ToLower();
            if (type == "root")
                return string.Empty;
            if (type == "collection")
                return "grid1";
            if ((type == "post") && string.IsNullOrEmpty(PathAction))
                return "createForm1";
            // "singleton" or any other type (DELETE, PUT, PATCH, etc.)
            return "editForm1";
        }

        public bool IsViewOfType(string view, string type)
        {
            foreach (var viewId in EnumerateViews(type, null))
                if (viewId.Equals(ConfigDictionary.NormalizeKey(view), StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        public string[] EnumerateViews(string type, string exclude)
        {
            return EnumerateViews(_controllerName, type, exclude);
        }

        public string[] EnumerateViews(string controllerName, string type, string exclude)
        {
            if (string.IsNullOrEmpty(type))
            {
                if (string.IsNullOrEmpty(PathKey))
                    type = "collection";
                else
                    type = "singleton";
            }
            type = type.ToLower();
            var list = new List<string>();
            var viewIterator = GetConfig(controllerName).Select("/c:dataController/c:views/c:view");
            while (viewIterator.MoveNext())
            {
                var viewId = viewIterator.Current.GetAttribute("id", string.Empty);
                if ((exclude != viewId && (DefaultView(type) == viewId)) || RESTfulResource.IsTagged(viewIterator.Current, ("rest-api-" + type)))
                    list.Add(viewId);
            }
            return list.ToArray();
        }

        public string ExtendRawUrlWith(string path, params object[] args)
        {
            return ReplaceRawUrlWith(string.Empty, false, path, args);
        }

        public string ExtendRawUrlWith(bool duplicateQueryParams, string path, params object[] args)
        {
            return ReplaceRawUrlWith(string.Empty, duplicateQueryParams, path, args);
        }

        public string ReplaceRawUrlWith(string startWith, bool duplicateQueryParams, string path, params object[] args)
        {
            if (args.Length > 0)
                path = string.Format(path, args);
            var url = RawUrl;
            var pathQueryParams = ToQueryParams(path);
            if (duplicateQueryParams)
                foreach (var queryParam in ToQueryParams(url))
                    if (!pathQueryParams.ContainsKey(queryParam.Key) && (queryParam.Key != "count" || !pathQueryParams.ContainsKey("page")))
                        pathQueryParams.Add(queryParam.Key, queryParam.Value);
            // strip down the query params from 'url' and 'path'
            var questionMarkIndexInUrl = url.IndexOf("?");
            if (questionMarkIndexInUrl > 0)
                url = url.Substring(0, questionMarkIndexInUrl);
            var isLatestVersion = false;
            if (url.EndsWith(("/" + LatestVersionLink)))
            {
                url = url.Substring(0, ((url.Length - LatestVersionLink.Length) - 1));
                isLatestVersion = true;
            }
            if (!string.IsNullOrEmpty(startWith))
            {
                if (!startWith.StartsWith("/"))
                    startWith = ("/" + startWith);
                var lastIndex = url.LastIndexOf(startWith);
                if (lastIndex > 0)
                    url = url.Substring(0, lastIndex);
            }
            var questionMarkIndex = path.IndexOf("?");
            if (questionMarkIndex >= 0)
                path = path.Substring(0, questionMarkIndex);
            if (!string.IsNullOrEmpty(path) && !path.StartsWith("/"))
                path = ("/" + path);
            url = (url + path);
            if (isLatestVersion)
                url = ((url + "/") + LatestVersionLink);
            var separator = "?";
            foreach (var queryParam in pathQueryParams)
            {
                url = string.Format("{0}{1}{2}={3}", url, separator, queryParam.Key, queryParam.Value);
                separator = "&";
            }
            return url;
        }

        public Dictionary<string, string> ToQueryParams(string url)
        {
            var queryParams = new Dictionary<string, string>();
            foreach (Match m in Regex.Matches(url, "(\\?|\\&)([^=]+)\\=([^&]+)"))
                queryParams[m.Groups[2].Value] = m.Groups[3].Value;
            return queryParams;
        }

        public ControllerConfiguration GetConfig(string controllerName)
        {
            controllerName = controllerName.Replace("-", string.Empty).Replace("_", string.Empty);
            ControllerConfiguration config = null;
            if (!_configList.TryGetValue(controllerName, out config))
                try
                {
                    config = DataControllerBase.CreateConfigurationInstance(GetType(), controllerName);
                    _configList[controllerName] = config;
                }
                catch (Exception)
                {
                    RESTfulResource.ThrowError(404, "invalid_path", "Controller '{0}' is not available.", controllerName);
                }
            return config;
        }

        public JProperty CreateLinks(JObject result, bool requiresHypermedia)
        {
            var links = CreateLinks(result);
            if ((links == null) && requiresHypermedia)
                RESTfulResource.ThrowError("invalid_settings", "Hypermedia is disabled. Set 'server.rest.hypermedia.enabled' to 'true' to use this resource.");
            return links;
        }

        public JProperty CreateLinks(JObject result)
        {
            if (Hypermedia)
            {
                var links = ((JProperty)(result.Property(LinksKey)));
                object linksDef = null;
                if (links == null)
                {
                    if (LinkStyle == "array")
                        linksDef = new JArray();
                    else
                        linksDef = new JObject();
                    links = new JProperty(LinksKey, linksDef);
                }
                else
                    result.Remove(LinksKey);
                if (LinksPosition == "first")
                {
                    if (!links.Equals(result.First))
                    {
                        if (linksDef == null)
                            result.Remove(LinksKey);
                        result.AddFirst(links);
                    }
                }
                else
                {
                    if (!links.Equals(result.Last))
                    {
                        if (linksDef == null)
                            result.Remove(LinksKey);
                        result.Add(links);
                    }
                }
                return links;
            }
            else
                return null;
        }

        public string EscapeLink(string hyperlink)
        {
            var questionMarkIndex = hyperlink.IndexOf("?");
            if (questionMarkIndex == -1)
                hyperlink = Uri.EscapeUriString(hyperlink);
            else
                hyperlink = (Uri.EscapeUriString(hyperlink.Substring(0, questionMarkIndex)) + hyperlink.Substring(questionMarkIndex));
            return hyperlink;
        }

        public static string ToServiceUrl(string url, params object[] args)
        {
            if (args.Length > 0)
                url = string.Format(url, args);
            if (Regex.IsMatch(url, "^(http|https)://"))
                return url;
            if (url.StartsWith("_self:"))
                return url.Substring(6);
            var serviceUrl = HttpContext.Current.Request.ApplicationPath;
            if (url.StartsWith("/v2"))
            {
                if (serviceUrl.Length == 1)
                    serviceUrl = string.Empty;
                return (serviceUrl + url);
            }
            if (url.StartsWith("~/"))
                return (serviceUrl + url.Substring(2));
            var urlBuilder = new StringBuilder(serviceUrl);
            if (!serviceUrl.EndsWith("/"))
                urlBuilder.Append("/");
            urlBuilder.Append("v2");
            if (!url.StartsWith("/"))
                urlBuilder.Append("/");
            urlBuilder.Append(url);
            return urlBuilder.ToString();
        }

        public string EnsurePublicApiKeyInUrl(string url)
        {
            var publicApiKey = RESTfulResource.PublicApiKey;
            if (!string.IsNullOrEmpty(publicApiKey) && !Regex.IsMatch(url, "(/oauth2|/v2/js/)"))
            {
                var apiKeyInUrl = Regex.Match(RawUrl, "(\\?|&)(x-api-key|api_key)=.+(&|$)");
                if (apiKeyInUrl.Success)
                {
                    var apiKeyQueryParam = string.Format("{0}={1}", apiKeyInUrl.Groups[2].Value, publicApiKey);
                    if (!url.Contains(apiKeyQueryParam))
                    {
                        if (!url.Contains("?"))
                            url = (url + "?");
                        else
                            url = (url + "&");
                        url = (url + apiKeyQueryParam);
                    }
                }
            }
            return url;
        }

        public JToken AddLinkProperty(JToken link, string propName, object propValue)
        {
            JToken result = null;
            if (link is JProperty)
                link = ((JProperty)(link)).Value;
            if (link is JObject)
            {
                result = new JProperty(propName, propValue);
                ((JObject)(link)).Add(result);
            }
            return result;
        }

        public JToken AddLink(string name, string method, JProperty links, string href, params object[] args)
        {
            return AddLink(name, string.Empty, method, links, href, args);
        }

        public JToken AddLink(string name, string suffix, string method, JProperty links, string href, params object[] args)
        {
            var hyperlink = EscapeLink(ToServiceUrl(href, args));
            name = ToApiFieldName(ToApiName(name));
            if (!string.IsNullOrEmpty(suffix))
                name = ((name + "-") + ToApiName(suffix));
            var schemaRegex = new Regex(string.Format("\\b{0}=\\w+\\b", _schemaKey));
            if (RequiresSchema && !schemaRegex.IsMatch(hyperlink))
            {
                if (!hyperlink.Contains("?"))
                    hyperlink = (hyperlink + "?");
                else
                    hyperlink = (hyperlink + "&");
                hyperlink = (hyperlink + _schemaKey);
                if (RequiresData)
                    hyperlink = (hyperlink + "=true");
                else
                    hyperlink = (hyperlink + "=only");
            }
            hyperlink = EnsurePublicApiKeyInUrl(hyperlink);
            var nameProp = ((JToken)(new JObject()));
            if (LinkStyle == "array")
            {
                ((JObject)(nameProp)).Add(new JProperty("href", hyperlink));
                ((JObject)(nameProp)).Add(new JProperty("rel", name));
                if (LinkMethod || method != "GET")
                    ((JObject)(nameProp)).Add(new JProperty("method", method));
            }
            else
            {
                nameProp = new JProperty(name, nameProp);
                if (LinkStyle == "string")
                    ((JProperty)(nameProp)).Value = hyperlink;
                else
                {
                    ((JObject)(((JProperty)(nameProp)).Value)).Add(new JProperty("href", hyperlink));
                    if (LinkMethod || method != "GET")
                        ((JObject)(((JProperty)(nameProp)).Value)).Add(new JProperty("method", method));
                }
            }
            if (name == ToApiName("selfLink"))
            {
                if (string.IsNullOrEmpty(PathKey))
                {
                    if (links.Value is JArray)
                        ((JArray)(links.Value)).AddFirst(nameProp);
                    else
                        ((JObject)(links.Value)).AddFirst(nameProp);
                }
                else
                {
                    if (links.Value is JArray)
                        ((JArray)(links.Value)).Add(nameProp);
                    else
                        ((JObject)(links.Value)).Add(nameProp);
                }
            }
            else
            {
                if (links.Value is JArray)
                    ((JArray)(links.Value)).Add(nameProp);
                else
                    ((JObject)(links.Value)).Add(nameProp);
            }
            return nameProp;
        }

        public virtual bool AllowEndpoint(string endpoint)
        {
            return ((EndpointValidator == null) || EndpointValidator.IsMatch(endpoint));
        }

        public virtual bool AllowController(string controllerName)
        {
            _lastAclRole = null;
            if (ApplicationServices.Create().IsSystemController(controllerName) || !HttpContext.Current.User.Identity.IsAuthenticated)
                return false;
            var allow = true;
            var acl = ((JObject)(ApplicationServicesBase.SettingsProperty("server.rest.acl")));
            if ((acl != null) && (acl.Count > 0))
            {
                allow = false;
                foreach (var rule in acl.Properties())
                    if (rule.Value.Type == JTokenType.Object)
                    {
                        Regex re = null;
                        try
                        {
                            re = new Regex(rule.Name, RegexOptions.IgnoreCase);
                        }
                        catch (Exception ex)
                        {
                            RESTfulResource.ThrowError(500, "invalid_config", "Rule 'server.rest.acl.\"{0}\"' specified in touch-settings.json is not a valid regular expression. Error: {1}", rule.Name, ex.Message);
                        }
                        if (re.IsMatch(controllerName))
                        {
                            // test user roles and scopes
                            foreach (var role in ((JObject)(rule.Value)).Properties())
                                if (UserScopes.Contains(role.Name) || HttpContext.Current.User.IsInRole(role.Name))
                                {
                                    allow = true;
                                    _lastAclRole = role;
                                    break;
                                }
                            if (allow)
                                break;
                        }
                    }
            }
            return allow;
        }

        public static string OAuth2FileName(string type, object id)
        {
            return string.Format("sys/oauth2/{0}/{1}.json", type, id);
        }

        public virtual JObject StandardScopes()
        {
            return TextUtility.ParseYamlOrJson(@"
openid:
  hint: View the unique user id, client app id, API endpoint, token issue and expiration date.
profile: 
  hint: View the user's last and first name, birthdate, gender, picture, and preferred language.
address:
  hint: View the user's preferred postal address.
email:
  hint: View the user's email address.
phone: 
  hint: View the user's phone number.
offline_access:
  hint: Access your data anytime.
");
        }

        public virtual JObject ApplicationScopes()
        {
            return ((JObject)(ApplicationServicesBase.SettingsProperty("server.rest.scopes", new JObject())));
        }

        public static string PathArrayToString(List<string> localPath, int startIndex)
        {
            return string.Join("/", localPath.GetRange(startIndex, (localPath.Count - startIndex)));
        }
    }

    public enum NameSetToken
    {

        Unknown,

        Name,

        LeftBracket,

        RightBracket,

        Comma,

        Eof,
    }

    public class NameSetParser
    {

        private string _parameter;

        private List<string> _list;

        private string _nameSet;

        private int _index;

        private NameSetToken _token;

        private string _tokenValue;

        private int _tokenIndex;

        private string _name;

        private Regex _re = new Regex("\\s*(?'Token'[\\w\\.\\-]+|\\{|\\}|\\,|\\S)");

        private Stack<string> _names;

        public NameSetParser(string parameter, JObject obj) :
                this(parameter, Convert.ToString(obj[parameter]))
        {
        }

        public NameSetParser(string parameter, string nameSet)
        {
            _parameter = parameter;
            _nameSet = nameSet;
            _index = 0;
            _tokenIndex = 0;
            _list = new List<string>();
            _names = new Stack<string>();
        }

        public NameSetToken NextToken()
        {
            _token = NameSetToken.Unknown;
            if (_index >= _nameSet.Length)
                _token = NameSetToken.Eof;
            else
            {
                var m = _re.Match(_nameSet, _index);
                if (m.Success)
                {
                    var token = m.Groups["Token"];
                    _tokenValue = token.Value;
                    _tokenIndex = token.Index;
                    _index = (_index + m.Value.Length);
                    if (_tokenValue == "{")
                        _token = NameSetToken.LeftBracket;
                    else
                    {
                        if (_tokenValue == "}")
                            _token = NameSetToken.RightBracket;
                        else
                        {
                            if (_tokenValue == ",")
                                _token = NameSetToken.Comma;
                            else
                            {
                                if (Regex.IsMatch(_tokenValue, "^\\w[\\w\\.\\-]*$"))
                                    _token = NameSetToken.Name;
                                else
                                {
                                    if (string.IsNullOrWhiteSpace(_tokenValue) && (_index >= _nameSet.Length))
                                        _token = NameSetToken.Eof;
                                }
                            }
                        }
                    }
                }
                else
                {
                    if (string.IsNullOrWhiteSpace(_nameSet.Substring(_index)))
                        _token = NameSetToken.Eof;
                }
            }
            return _token;
        }

        /// goal ::= name-list | { name-list }
        /// name-list ::= name-def | name-def name-list | name-def , name-list
        /// name-def ::= name | name { name-list }
        public List<string> Execute()
        {
            if (string.IsNullOrEmpty(_nameSet))
                return null;
            Goal();
            if (!NameList() && _token != NameSetToken.Eof)
                ThrowError(string.Empty);
            return _list;
        }

        protected bool Goal()
        {
            NextToken();
            if (_token == NameSetToken.LeftBracket)
            {
                NextToken();
                if (NameList())
                {
                    if (_token == NameSetToken.RightBracket)
                    {
                        NextToken();
                        return true;
                    }
                    else
                    {
                        ThrowError("Symbol '}' is expected.");
                        return false;
                    }
                }
                else
                {
                    ThrowError("A list of names is expected.");
                    return false;
                }
            }
            else
                return NameList();
        }

        protected bool NameList()
        {
            var first = true;
            var comma = false;
            while (true)
                if (first)
                {
                    if (!NameDef())
                        break;
                    first = false;
                }
                else
                {
                    if (_token == NameSetToken.Comma)
                    {
                        NextToken();
                        comma = true;
                    }
                    if (NameDef())
                        comma = false;
                    else
                        break;
                }
            if (comma)
            {
                _tokenValue = ",";
                ThrowError("The name is expected.");
                return false;
            }
            return !first;
        }

        protected bool NameDef()
        {
            if (Name())
            {
                if (_token == NameSetToken.LeftBracket)
                {
                    _names.Push(_name);
                    NextToken();
                    if (NameList())
                    {
                        if (_token == NameSetToken.RightBracket)
                        {
                            _names.Pop();
                            NextToken();
                            return true;
                        }
                        else
                        {
                            ThrowError("Symbol '}' is expected.");
                            return false;
                        }
                    }
                    else
                    {
                        if (_token == NameSetToken.RightBracket)
                        {
                            _names.Pop();
                            NextToken();
                            return true;
                        }
                        else
                        {
                            ThrowError("A list of names or '}' is expected.");
                            return false;
                        }
                    }
                }
                else
                    return true;
            }
            else
                return false;
        }

        protected bool Name()
        {
            if (_token == NameSetToken.Name)
            {
                _name = _tokenValue;
                // save the name
                var qualifiedName = string.Empty;
                foreach (var n in _names)
                    qualifiedName = (n + ("." + qualifiedName));
                if (string.IsNullOrEmpty(qualifiedName))
                    qualifiedName = _name;
                else
                    qualifiedName = (qualifiedName + _name);
                _list.Add(qualifiedName);
                // continue parsing
                NextToken();
                return true;
            }
            else
                return false;
        }

        protected void ThrowError(string error, params object[] args)
        {
            var index = _tokenIndex;
            var s = _nameSet;
            if (_token == NameSetToken.Eof)
            {
                index = s.Length;
                _tokenValue = "EOF";
                s = (s + _tokenValue);
            }
            // create an error message
            if (args.Length > 0)
                error = string.Format(error, args);
            if (!string.IsNullOrEmpty(error))
                error = (error + " ");
            var contextLength = 100;
            var prefix = s.Substring(Math.Max(0, (index - contextLength)), Math.Min(contextLength, index));
            if ((prefix.Length >= contextLength) && (index >= (contextLength - 1)))
                prefix = ("..." + prefix.TrimStart());
            else
                prefix = prefix.TrimStart();
            var suffix = s.Substring(index, Math.Min((s.Length - index), contextLength)).TrimEnd();
            if (suffix.Length >= contextLength)
                suffix = (suffix + "...");
            var sample = (prefix + (">>>>>>>" + suffix));
            var precedingText = s.Substring(0, index);
            var row = Regex.Split(precedingText, "\n").Length;
            var col = ((index - Math.Max(0, precedingText.LastIndexOf("\n"))) + 1);
            RESTfulResource.ThrowError("invalid_argument", "Invalid definition of the '{1}' parameter. {0}Unexpected token '{2}' (Ln {3}, Col {4}): {5}", error, _parameter, _tokenValue, row, col, sample);
        }
    }

    public partial class V2ServiceRequestHandler : V2ServiceRequestHandlerBase
    {
    }

    public class OpConstraint
    {

        private string _name;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _op;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private int _minValCount;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private int _maxValCount;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _join;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _negativeOp;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _arrayOp;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private bool _urlArrays;

        public string Name
        {
            get
            {
                return _name;
            }
            set
            {
                foreach (var o in value.Split(new char[] {
                            ','}, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (string.IsNullOrEmpty(_name))
                        _name = o;
                    RESTfulResourceBase.Operations[o] = this;
                }
            }
        }

        public string Op
        {
            get
            {
                return _op;
            }
            set
            {
                _op = value;
            }
        }

        public int MinValCount
        {
            get
            {
                return _minValCount;
            }
            set
            {
                _minValCount = value;
            }
        }

        public int MaxValCount
        {
            get
            {
                return _maxValCount;
            }
            set
            {
                _maxValCount = value;
            }
        }

        public string Join
        {
            get
            {
                return _join;
            }
            set
            {
                _join = value;
            }
        }

        /// false
        public string NegativeOp
        {
            get
            {
                return _negativeOp;
            }
            set
            {
                _negativeOp = value;
            }
        }

        /// [1, 2, 3]
        public string ArrayOp
        {
            get
            {
                return _arrayOp;
            }
            set
            {
                _arrayOp = value;
            }
        }

        public bool UrlArrays
        {
            get
            {
                return _urlArrays;
            }
            set
            {
                _urlArrays = value;
            }
        }
    }

    public class FilterBuilder
    {

        public static string[] Keywords = new string[] {
                "and",
                "not",
                "or",
                "contains",
                "startswith",
                "endswith",
                "has",
                "in"};

        private RESTfulResourceConfiguration _options;

        private ConfigDictionary _fieldMap;

        private string _filterExpression;

        public FilterBuilder Initialize(string filterExpression, RESTfulResource options)
        {
            _filterExpression = filterExpression;
            _options = options;
            _fieldMap = options.FieldMap;
            return this;
        }

        public static FilterBuilder Create()
        {
            return new FilterBuilder();
        }

        public void Execute()
        {
            if (string.IsNullOrEmpty(_filterExpression))
                return;
            // set the original filter and parameters
            _filterExpression = Regex.Replace(_filterExpression, "(\\')(.*?)((?<!\\\\)\\'|$)", ReplaceStringConstants);
            _filterExpression = Regex.Replace(_filterExpression, "(@FltrExpParam\\d+|[a-zA-Z_]\\w*)", CheckNames);
            _filterExpression = Regex.Replace(_filterExpression, "(?<!@)(\\w+)", ReplaceBooleans);
            _filterExpression = Regex.Replace(_filterExpression, "(\\w+)\\s+(contains|endsWith|startsWith)\\s+(\\S+)", ReplaceContains, RegexOptions.IgnoreCase);
            // set the new filter for further processing
            HttpContext.Current.Items[(_options.ControllerName + "_FilterExpression")] = _filterExpression;
            HttpContext.Current.Items[(_options.ControllerName + "_FilterParameters")] = _options.Parameters;
        }

        private string AddFilterExpressionParameter(object value)
        {
            var parameters = _options.Parameters;
            var name = ("@FltrExpParam" + parameters.Count.ToString());
            parameters.Add(name, value);
            return name;
        }

        private string ReplaceStringConstants(Match m)
        {
            if (string.IsNullOrEmpty(m.Groups[3].Value))
                RESTfulResource.ThrowError("invalid_argument", "Unclosed single quote in the '{0}' parameter.", _options.FilterParam);
            return (" " + (AddFilterExpressionParameter(m.Groups[2].Value.Replace("\\", string.Empty)) + " "));
        }

        private string ReplaceBooleans(Match m)
        {
            var fieldName = m.Value;
            XPathNavigator fieldNav = null;
            if (_fieldMap.TryGetValue(fieldName, out fieldNav))
            {
                if (fieldNav.GetAttribute("type", string.Empty) == "Boolean")
                    return string.Format("({0}={1})", fieldName, AddFilterExpressionParameter(true));
            }
            return fieldName;
        }

        private string ReplaceContains(Match m)
        {
            var fieldName = m.Groups[1].Value;
            var op = m.Groups[2].Value.ToLower();
            var value = m.Groups[3].Value;
            var sb = new StringBuilder();
            if (!_fieldMap.ContainsKey(fieldName))
                RESTfulResource.ThrowError(400, true, "invalid_argument", "Unexpected field '{0}' is specified in the '{1}' parameter.", fieldName, _options.FilterParam);
            object paramValue = null;
            if (_options.Parameters.TryGetValue(value, out paramValue))
            {
                var valueString = _options.Parameters[value].ToString();
                if (!valueString.Contains("%"))
                {
                    if (op == "contains")
                        valueString = string.Format("%{0}%", valueString);
                    else
                    {
                        if (op == "startswith")
                            valueString = (valueString + "%");
                        else
                            valueString = ("%" + valueString);
                    }
                    _options.Parameters[value] = valueString;
                    paramValue = value;
                }
            }
            else
            {
                if (!value.Contains("%"))
                {
                    if (op == "contains")
                        value = string.Format("%{0}%", value);
                    else
                    {
                        if (op == "startswith")
                            value = (value + "%");
                        else
                            value = ("%" + value);
                    }
                }
                paramValue = AddFilterExpressionParameter(value);
            }
            return string.Format("({0} like {1})", fieldName, paramValue);
        }

        private string CheckNames(Match m)
        {
            var name = m.Value;
            if (name.StartsWith("@"))
            {
                if (!_options.Parameters.ContainsKey(name))
                    RESTfulResource.ThrowError("invalid_argument", "Symbol '@' is not allowed in the '{0}' parameter.", _options.FilterParam);
                else
                    return m.Value;
            }
            if (!_fieldMap.ContainsKey(name))
            {
                if (Array.IndexOf(Keywords, name.ToLower()) == -1)
                    RESTfulResource.ThrowError(400, true, "invalid_argument", "Unexpected field '{0}' is specified in the '{1}' parameter.", name, _options.FilterParam);
                else
                    return m.Value;
            }
            return m.Value;
        }
    }

    public class EmbeddedLink
    {

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _rel;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _href;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private JObject _target;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private JObject _response;

        public string Rel
        {
            get
            {
                return _rel;
            }
            set
            {
                _rel = value;
            }
        }

        public string Href
        {
            get
            {
                return _href;
            }
            set
            {
                _href = value;
            }
        }

        public JObject Target
        {
            get
            {
                return _target;
            }
            set
            {
                _target = value;
            }
        }

        public JObject Response
        {
            get
            {
                return _response;
            }
            set
            {
                _response = value;
            }
        }
    }

    public class EmbeddingEngine
    {

        private List<EmbeddedLink> _links;

        private List<string> _embed;

        private RESTfulResourceConfiguration _options;

        private JObject _target;

        public EmbeddingEngine(JObject target, List<string> embed, RESTfulResourceConfiguration options)
        {
            _options = options;
            _links = new List<EmbeddedLink>();
            _target = target;
            _embed = embed;
            for (var i = 0; (i < embed.Count); i++)
                _embed[i] = ConfigDictionary.NormalizeKey(_embed[i]);
            EmbedLinks(_target);
        }

        public static string Execute(string href, RESTfulResourceConfiguration options)
        {
            var currentRequest = HttpContext.Current.Request;
            var server = Regex.Match(currentRequest.Url.ToString(), "^(.+?)/v2(\\/)");
            var headers = currentRequest.Headers;
            var url = (server.Groups[1].Value + href);
            var cachedResult = ((string)(HttpContext.Current.Cache[url]));
            if (!string.IsNullOrEmpty(cachedResult))
                return cachedResult;
            var request = ((HttpWebRequest)(WebRequest.Create(url)));
            foreach (string key in headers)
                if (!WebHeaderCollection.IsRestricted(key))
                    request.Headers[key] = headers[key];
            if (options != null)
            {
                if (options.RemoveLinks)
                    request.Headers["X-Restful-HypermediaEmbeddedReplace"] = "true";
                request.Headers["X-Restful-OutputContentType"] = options.OutputContentType;
            }
            request.Method = "GET";
            request.Accept = "*/*";
            using (var response = request.GetResponse())
            {
                using (var responseStream = response.GetResponseStream())
                {
                    var stream = responseStream;
                    var contentEncoding = response.Headers["Content-Encoding"];
                    var cacheControl = response.Headers["Cache-Control"];
                    if (contentEncoding == "gzip")
                        stream = new GZipStream(stream, CompressionMode.Decompress);
                    else
                    {
                        if (contentEncoding == "deflate")
                            stream = new DeflateStream(stream, CompressionMode.Decompress);
                    }
                    var result = new StreamReader(stream).ReadToEnd();
                    if (!string.IsNullOrEmpty(cacheControl))
                    {
                        var maxAge = Regex.Match(cacheControl, "max-age=(\\d+)");
                        if (maxAge.Success)
                            try
                            {
                                HttpContext.Current.Cache.Add(url, result, null, DateTime.Now.AddSeconds(Convert.ToInt32(maxAge.Groups[1].Value)), Cache.NoSlidingExpiration, CacheItemPriority.Normal, null);
                            }
                            catch (Exception)
                            {
                            }
                    }
                    return result;
                }
            }
        }

        public void Execute()
        {
            var index = 0;
            while (index < _links.Count)
            {
                var link = _links[index];
                JObject result = null;
                try
                {
                    // prepare new _embed instruction
                    var embedList = new List<string>();
                    // prepare the field filter
                    var href = link.Href;
                    var linkNamePrefix = (ConfigDictionary.NormalizeKey(link.Rel) + ".");
                    var fieldFilter = new List<string>();
                    foreach (var name in _embed)
                        if (name.StartsWith(linkNamePrefix))
                        {
                            var field = name.Substring(linkNamePrefix.Length);
                            if (field.Contains("*"))
                            {
                                var periodStarIndex = field.IndexOf(".*");
                                if (periodStarIndex >= 0)
                                    embedList.Add(field.Substring(0, periodStarIndex));
                            }
                            else
                                fieldFilter.Add(field);
                        }
                    if (fieldFilter.Count > 0)
                    {
                        var m = Regex.Match(href, "(\\?|\\&)fields=(.+?)(\\&|$)");
                        var linkFieldFilter = new NameSetParser("fields", m.Groups[2].Value).Execute();
                        if (linkFieldFilter != null)
                        {
                            foreach (var name in fieldFilter)
                                if (!linkFieldFilter.Contains(name))
                                    linkFieldFilter.Add(name);
                            fieldFilter = linkFieldFilter;
                            href = (href.Substring(0, m.Groups[2].Index) + href.Substring((m.Groups[3].Index + 1)));
                        }
                        if (!href.Contains("?"))
                            href = (href + "?");
                        else
                        {
                            if (!href.EndsWith("&"))
                                href = (href + "&");
                        }
                        href = ((href + "fields=") + string.Join(",", fieldFilter));
                    }
                    if (embedList.Count > 0)
                    {
                        if (!href.Contains("?"))
                            href = (href + "?");
                        else
                        {
                            if (!href.EndsWith("&"))
                                href = (href + "&");
                        }
                        href = string.Format("{0}{1}={2}", href, _options.EmbedParam, string.Join(",", embedList));
                    }
                    result = JObject.Parse(EmbeddingEngine.Execute(href, _options));
                }
                catch (WebException ex)
                {
                    var response = ex.Response;
                    var stream = response.GetResponseStream();
                    var contentEncoding = response.Headers["Content-Encoding"];
                    if (contentEncoding == "gzip")
                        stream = new GZipStream(stream, CompressionMode.Decompress);
                    var body = new StreamReader(stream).ReadToEnd();
                    if (response.ContentType.StartsWith("application/json"))
                        result = JObject.Parse(body);
                    else
                        result = new JObject(new JProperty("href", link.Href), new JProperty("status", ex.Status.ToString()), new JProperty("error", ex.Message), new JProperty("body", body));
                }
                catch (Exception ex)
                {
                    // handle the "bad" link
                    result = new JObject(new JProperty("href", link.Href), new JProperty("error", ex.Message));
                }
                // add the result to the link target
                if (_options.ReplaceEmbedded)
                    link.Target[link.Rel] = result;
                else
                {
                    var embedded = ((JObject)(link.Target[_options.EmbeddedKey]));
                    if (embedded == null)
                    {
                        embedded = new JObject();
                        link.Target.Add(new JProperty(_options.EmbeddedKey, embedded));
                    }
                    embedded.Add(link.Rel, result);
                }
                index++;
            }
        }

        public virtual void EmbedLinks(JObject target)
        {
            foreach (var p in target.Properties())
                if (p.Name == _options.LinksKey)
                {
                    if (p.Value.Type == JTokenType.Object)
                        foreach (var l in ((JObject)(p.Value)).Properties())
                        {
                            var normalName = ConfigDictionary.NormalizeKey(l.Name);
                            if (l.Value.Type != JTokenType.Object)
                            {
                                if (_embed.Contains(normalName) || _embed.Contains((normalName + ".*")))
                                {
                                    var el = new EmbeddedLink()
                                    {
                                        Rel = l.Name,
                                        Href = Convert.ToString(l.Value),
                                        Target = target
                                    };
                                    _links.Add(el);
                                }
                            }
                            else
                            {
                                if (Convert.ToBoolean(l.Value[_options.EmbeddableKey]) && (_embed.Contains(normalName) || _embed.Contains((normalName + ".*"))))
                                {
                                    var el = new EmbeddedLink()
                                    {
                                        Rel = l.Name,
                                        Href = Convert.ToString(l.Value["href"]),
                                        Target = target
                                    };
                                    _links.Add(el);
                                }
                            }
                        }
                    else
                    {
                        if (p.Value.Type == JTokenType.Array)
                            foreach (JObject l in p.Value)
                            {
                                var rel = Convert.ToString(l["rel"]);
                                var normalRel = ConfigDictionary.NormalizeKey(rel);
                                if ((Convert.ToBoolean(l[_options.EmbeddableKey]) && _embed.Contains(normalRel)) || _embed.Contains((normalRel + ".*")))
                                {
                                    var el = new EmbeddedLink()
                                    {
                                        Rel = rel,
                                        Href = Convert.ToString(l["href"]),
                                        Target = target
                                    };
                                    _links.Add(el);
                                }
                            }
                    }
                }
                else
                {
                    if (p.Value.Type == JTokenType.Object)
                        EmbedLinks(((JObject)(p.Value)));
                    else
                    {
                        if (p.Value.Type == JTokenType.Array)
                            foreach (var elem in p.Value)
                                if (elem.Type == JTokenType.Object)
                                    EmbedLinks(((JObject)(elem)));
                    }
                }
        }
    }

    public class V2ServiceRequestHandlerBase : ServiceRequestHandler
    {

        public static string[] SupportedMethods = new string[] {
                "GET",
                "POST",
                "PATCH",
                "PUT",
                "DELETE"};

        public static string[] SupportedParameters = new string[] {
                "controller",
                "view",
                "sort",
                "limit",
                "page",
                "fields",
                "count",
                "aggregates",
                "format"};

        public V2ServiceRequestHandlerBase()
        {
        }

        public override string[] AllowedMethods
        {
            get
            {
                return SupportedMethods;
            }
        }

        public override bool RequiresAuthentication
        {
            get
            {
                return false;
            }
        }

        public override bool WrapOutput
        {
            get
            {
                return false;
            }
        }

        public virtual int MaxLimit
        {
            get
            {
                return 1000;
            }
        }

        public override void ClearHeaders()
        {
            var response = HttpContext.Current.Response;
            response.Cookies.Clear();
            response.Headers.Remove("Set-Cookie");
        }

        public override object HandleException(JObject args, Exception ex)
        {
            var err = "unauthorized";
            var statusCode = -1;
            if ((ex is HttpException) && (((HttpException)(ex)).GetHttpCode() == 405))
                err = "invalid_method";
            if (ex is RESTfulResourceException)
            {
                err = ((RESTfulResourceException)(ex)).Error;
                statusCode = ((RESTfulResourceException)(ex)).HttpCode;
            }
            if (statusCode != -1)
                HttpContext.Current.Response.StatusCode = statusCode;
            return ApplicationServicesBase.Current.JsonError(err, ex.Message);
        }

        public override object Validate(DataControllerService service, JObject args)
        {
            if (!Convert.ToBoolean(ApplicationServicesBase.SettingsProperty("server.rest.enabled")))
                RESTfulResource.ThrowError(403, "unavailable", "REST API is not enabled.");
            if (RESTfulResource.IsOAuth)
            {
                if (!Convert.ToBoolean(ApplicationServicesBase.SettingsProperty("server.rest.authorization.oauth2.enabled", true)))
                    RESTfulResource.ThrowError(403, "unavailable", "Authentication with the bearer token is not enabled.");
                return null;
            }
            var context = HttpContext.Current;
            if (!context.User.Identity.IsAuthenticated)
            {
                if (RESTfulResource.AnonymousAccessSupported)
                    return null;
                if (string.IsNullOrEmpty(context.Request.Headers["x-api-key"]) && (string.IsNullOrEmpty(context.Request.QueryString["api_key"]) && string.IsNullOrEmpty(context.Request.QueryString["x-api-key"])))
                    RESTfulResource.ThrowError(403, "missing_api_key", "RESTful API engine requires an API key or an access token for '{0}' resource.", context.Request.Path);
                else
                    RESTfulResource.ThrowError(403, "invalid_api_key", "RESTful API engine requires a valid API key or an access token for '{0}' resource.", context.Request.Path);
            }
            return base.Validate(service, args);
        }

        public virtual string[] GetDataControllerList()
        {
            return ControllerConfigurationUtility.GetDataControllerList();
        }

        public override object HandleRequest(DataControllerService service, JObject args)
        {
            var context = HttpContext.Current;
            if (context.Request.HttpMethod == "GET")
                args = new JObject();
            var result = GraphQLExecute(service, args);
            if (result == null)
                result = RESTfulExecute(service, args);
            return result;
        }

        protected string[] PropToStringArray(JToken prop, bool allowSpaceSeparator)
        {
            if (prop != null)
            {
                if (prop is JArray)
                    return prop.ToObject<string[]>();
                else
                {
                    if (!((prop is JValue)))
                        RESTfulResource.ThrowError("invalid_parameter", "Parmeter '{0}' must be a value or an array.", ((JProperty)(prop.Parent)).Name);
                }
                var list = Convert.ToString(prop).Trim();
                if (list.Length == 0)
                    return new string[0];
                if (allowSpaceSeparator)
                {
                    list = Regex.Replace(list, "\\s*,\\s*", " ");
                    return Regex.Split(list, "\\s+");
                }
                else
                    return Regex.Split(list, "\\s*,\\s*");
            }
            return null;
        }

        public virtual JObject ToApiEndpoint(RESTfulResourceConfiguration options)
        {
            var schema = "only";
            if (Convert.ToBoolean(ApplicationServicesBase.SettingsProperty("server.rest.schema.data", false)))
                schema = "true";
            var result = new JObject();
            var links = options.CreateLinks(result);
            if (Convert.ToBoolean(ApplicationServicesBase.SettingsProperty("server.rest.authorization.oauth2.enabled", true)))
            {
                if (links != null)
                {
                    if (RESTfulResource.IsOAuth)
                    {
                        var appScopes = ((JObject)(ApplicationServicesBase.SettingsProperty("server.rest.scopes", new JObject())));
                        var standardScopes = options.StandardScopes();
                        var standardScopeList = new List<JProperty>(standardScopes.Properties());
                        standardScopeList.Reverse();
                        foreach (var scopeProp in standardScopeList)
                            if (appScopes[scopeProp.Name] == null)
                                appScopes.AddFirst(new JProperty(scopeProp.Name, ((JObject)(scopeProp.Value))));
                        result["scopes"] = appScopes;
                        if (RESTfulResource.IsAuthorized("post/apps", RESTfulResource.OAuth2Schema))
                            options.AddLink("apps", "GET", links, "~/oauth2/v2/apps");
                        options.AddLink("authorize", "GET", links, "~/oauth2/v2/auth");
                        options.AddLink("token", "POST", links, "~/oauth2/v2/token");
                        options.AddLink("tokeninfo", "GET", links, "~/oauth2/v2/tokeninfo");
                        options.AddLink("userinfo", "POST", links, "~/oauth2/v2/userinfo");
                        options.AddLink("revoke", "POST", links, "~/oauth2/v2/revoke");
                        options.AddLink("authorize-client-native", "POST", links, "~/oauth2/v2/auth/pkce");
                        options.AddLink("authorize-client-spa", "POST", links, "~/oauth2/v2/auth/spa");
                        options.AddLink("authorize-server", "POST", links, "~/oauth2/v2/auth/server");
                        if (!options.RequiresSchema)
                            options.AddLink("schema", "GET", links, string.Format("~/oauth2/v2?{0}=true", options.SchemaKey));
                    }
                    else
                        options.AddLink("oauth2", "GET", links, "~/oauth2/v2");
                }
            }
            if (!RESTfulResource.IsOAuth)
            {
                if (links != null)
                    options.AddLink("restful.js", "GET", links, "~/v2/js/restful-2.0.1.js");
                var publicApiKey = Convert.ToString(RESTfulResource.PublicApiKeyInPath);
                if (!string.IsNullOrEmpty(publicApiKey))
                    publicApiKey = (publicApiKey + "/");
                foreach (var controllerName in GetDataControllerList())
                {
                    options.ControllerName = controllerName;
                    if (options.AllowEndpoint(options.ControllerResource) && options.AllowController(controllerName))
                    {
                        var controllerObject = new JObject();
                        var controllerLinks = options.CreateLinks(controllerObject);
                        if (controllerLinks != null)
                        {
                            var selfControl = options.AddLink("selfLink", "GET", controllerLinks, "{0}{1}?count=true", publicApiKey, options.ControllerResource);
                            var cacheItem = new DataCacheItem(options.ControllerName);
                            if (cacheItem.IsMatch)
                            {
                                options.AddLink("latestVersionLink", "GET", controllerLinks, "{0}{1}/{2}?count=true", publicApiKey, options.ControllerResource, options.LatestVersionLink);
                                options.AddLinkProperty(selfControl, "max-age", cacheItem.Duration);
                            }
                            options.AddLink("firstLink", "GET", controllerLinks, "{0}{1}?page=0&limit={2}", publicApiKey, options.ControllerResource, options.PageSize);
                            if (options.AllowsSchema)
                                options.AddLink("schemaLink", "GET", controllerLinks, "{0}{1}?count=true&{2}={3}", publicApiKey, options.ControllerResource, options.SchemaKey, schema);
                        }
                        result.Add(new JProperty(options.ToPathName(controllerName), controllerObject));
                    }
                }
                options.ControllerName = null;
            }
            return result;
        }

        public virtual object RESTfulExecute(DataControllerService service, JObject args)
        {
            RESTfulResource resource = null;
            DataCacheItem cacheItem = null;
            var payload = args;
            var result = new JObject();
            var request = HttpContext.Current.Request;
            var response = HttpContext.Current.Response;
            try
            {
                resource = new RESTfulResource();
                if (!resource.IsImmutable)
                    args = new JObject();
                if (string.IsNullOrEmpty(resource.OutputContentType))
                    resource.OutputContentType = this.OutputContentType();
                resource.Navigate(args);
                if (resource.IsImmutable)
                {
                    cacheItem = new DataCacheItem(resource.Controller, request.RawUrl);
                    if (cacheItem.HasValue)
                    {
                        cacheItem.SetMaxAge();
                        return cacheItem.Value;
                    }
                }
                if (resource.ExecuteWithSchema(resource.CustomSchema, payload, result))
                    return result;
                if (resource.IsReport)
                    args = new JObject();
                var supportedGetParameters = new List<string>(SupportedParameters);
                foreach (var s in new string[] {
                        resource.LinksKey,
                        resource.SchemaKey,
                        resource.EmbedParam,
                        "x-api-key",
                        "api_key"})
                    supportedGetParameters.Add(resource.ToApiName(s));
                supportedGetParameters.Add(resource.FilterParam);
                if (string.IsNullOrEmpty(resource.Controller))
                {
                    if (resource.IsImmutable)
                    {
                        if (Convert.ToBoolean(ApplicationServicesBase.SettingsProperty("server.rest.schema.enabled", true)))
                            return ToApiEndpoint(resource);
                        else
                            RESTfulResource.ThrowError("introspection_error", "API introspection is disabled.");
                    }
                    else
                        RESTfulResource.ThrowError("invalid_path", "Specify the name of the controller in the path.");
                }
                var filterExpression = request.QueryString[resource.FilterParam];
                if (filterExpression != null)
                    FilterBuilder.Create().Initialize(filterExpression, resource).Execute();
                var filter = new JObject();
                if (resource.Filter.Count > 0)
                {
                    args.Add(new JProperty("filter", filter));
                    foreach (var filterField in resource.Filter)
                        filter.Add(new JProperty(filterField.Name, filterField.Value));
                }
                // analyze the query string parameters
                foreach (string p in request.QueryString)
                    if (p != null)
                    {
                        XPathNavigator fieldNav = null;
                        if (resource.FieldMap.TryGetValue(p, out fieldNav))
                        {
                            var fieldName = fieldNav.GetAttribute("name", string.Empty);
                            if (filter.ContainsKey(fieldName))
                                RESTfulResource.ThrowError("invalid_path", "Query parameer '{0}' is already specified as the entity '{1}' in the path.", p, filter[fieldName]);
                            else
                            {
                                if (!resource.IsCollection)
                                    RESTfulResource.ThrowError("invalid_parameter", "Parameter '{0}' is not allowed.", p);
                                else
                                {
                                    if (resource.IsImmutable)
                                        filter.Add(new JProperty(fieldName, request.QueryString[p]));
                                    else
                                        RESTfulResource.ThrowError("invalid_parameter", "Parameter '{0}' is not allowed with the {1} method.", p, request.HttpMethod);
                                }
                            }
                        }
                        else
                        {
                            if (p != resource.FilterParam)
                                args[p] = request.QueryString[p];
                        }
                    }
                if (filter.Count > 0)
                    args["filter"] = filter;
                if (!(((resource.IsCollection && resource.IsImmutable) || resource.IsReport)))
                    foreach (var paramName in new string[] {
                            "limit",
                            "sort",
                            "count",
                            "filterParam"})
                    {
                        var name = resource.ToApiName(paramName);
                        if (!string.IsNullOrEmpty(request.QueryString[name]))
                            RESTfulResource.ThrowError("invalid_parameter", "Parameter '{0}' is not allowed.", name);
                    }
                if (!resource.IsCollection)
                    resource.SetPropertyValue(args, "limit", 1);
                if (!string.IsNullOrEmpty(resource.Field))
                {
                    if (args["fields"] != null)
                        RESTfulResource.ThrowError("invalid_parameter", "Parameter 'fields' is not allowed.");
                    var pathField = resource.ToApiFieldName(resource.Field);
                    if (!resource.FieldMap.ContainsKey(pathField))
                        RESTfulResource.ThrowError(400, true, "invalid_path", "Unexpected field '{0}' is specified in the path.", pathField);
                    else
                        args["fields"] = pathField;
                }
                // calculate the page size and index
                var limit = resource.GetProperty(args, "limit", "Int32");
                var pageSize = Convert.ToInt32(limit);
                if ((limit != null) && (pageSize <= 0))
                    RESTfulResource.ThrowError("invalid_argument", "Parameter 'limit' must be greater than zero.");
                if ((limit == null) && (pageSize == 0))
                    pageSize = resource.Limit;
                var page = resource.GetProperty(args, "page", "Int32");
                var pageIndex = Convert.ToInt32(page);
                if (pageSize > MaxLimit)
                    pageSize = MaxLimit;
                // process the field filter
                var embed = new List<string>();
                var fieldFilter = new NameSetParser("fields", args).Execute();
                if (fieldFilter != null)
                {
                    var enumeratedFilterFields = new List<string>();
                    var i = 0;
                    while (i < fieldFilter.Count)
                    {
                        var fieldName = fieldFilter[i];
                        var periodIndex = fieldName.LastIndexOf('.');
                        if (periodIndex >= 0)
                        {
                            var parentFieldName = fieldName.Substring(0, periodIndex);
                            if (!embed.Contains(parentFieldName))
                                embed.Add(parentFieldName);
                            embed.Add(fieldName);
                            fieldFilter.RemoveAt(i);
                        }
                        else
                        {
                            if (resource.OutputStyle == "snake")
                                fieldName = fieldName.Replace("_", string.Empty);
                            if (enumeratedFilterFields.Contains(fieldName))
                                RESTfulResource.ThrowError("invalid_filter", "Duplicate field '{0}' in the filter.", fieldName);
                            else
                            {
                                if (!fieldName.Contains("."))
                                {
                                    fieldFilter[i] = fieldName;
                                    enumeratedFilterFields.Add(fieldName);
                                }
                            }
                            i++;
                        }
                    }
                }
                // prepare the basic controller information
                if (resource.IsImmutable)
                    foreach (var propName in args)
                        if (!supportedGetParameters.Contains(propName.Key))
                            RESTfulResource.ThrowError("invalid_parameter", "Parameter '{0}' is not supported.", propName.Key);
                args["controller"] = resource.Controller;
                args["view"] = resource.View;
                // prepare the GET request
                var r = new PageRequest()
                {
                    Controller = resource.ControllerName,
                    View = resource.PathView,
                    RequiresMetaData = true,
                    PageIndex = pageIndex,
                    PageSize = pageSize
                };
                var totalCount = resource.GetProperty(args, "count", "Boolean");
                if ((page != null) && ((totalCount == null) || (Convert.ToBoolean(totalCount) != false || (!resource.IsRoot && resource.IsCollection))))
                    r.RequiresRowCount = true;
                r.MetadataFilter = new string[] {
                        "fields"};
                if (fieldFilter != null)
                {
                    for (var i = 0; (i < fieldFilter.Count); i++)
                    {
                        XPathNavigator fieldNav = null;
                        if (resource.FieldMap.TryGetValue(fieldFilter[i], out fieldNav))
                            fieldFilter[i] = fieldNav.GetAttribute("name", string.Empty);
                    }
                    r.FieldFilter = fieldFilter.ToArray();
                    if (fieldFilter.Count == 0)
                        r.RequiresRowCount = true;
                }
                if (totalCount != null)
                    r.RequiresRowCount = Convert.ToBoolean(totalCount);
                else
                {
                    if (pageSize == 0)
                        r.RequiresRowCount = true;
                }
                var aggregates = args["aggregates"];
                if (aggregates != null)
                {
                    r.DoesNotRequireAggregates = !Convert.ToBoolean(aggregates);
                    if (!r.DoesNotRequireAggregates)
                        r.RequiresRowCount = true;
                }
                else
                    r.DoesNotRequireAggregates = true;
                r.SortExpression = ToSortExpression(args["sort"], resource);
                r.Filter = resource.ToFilter(args);
                // *** create CSV output ***
                var viewPage = resource.Execute(r, payload, result);
                if ((viewPage != null) && ((request.AcceptTypes != null) && (Array.IndexOf(request.AcceptTypes, "text/csv") >= 0)))
                {
                    var controller = ((DataControllerBase)(ControllerFactory.CreateDataController()));
                    response.ContentType = "text/csv; charset=utf-8";
                    var byteOrder = Encoding.UTF8.GetPreamble();
                    response.OutputStream.Write(byteOrder, 0, byteOrder.Length);
                    using (var sw = new StreamWriter(response.OutputStream))
                    {
                        controller.ExportDataAsCsv(viewPage, new DataTableReader(viewPage.ToDataTable()), sw, "all");
                        sw.Flush();
                    }
                    return null;
                }
                // *** create a report ***
                if (viewPage == null)
                {
                    if (resource.IsReport)
                    {
                        if (!resource.RequiresSchema)
                            result = null;
                    }
                    else
                        resource.CreateOwnerCollectionLinks(result);
                    return result;
                }
                // *** produce the resource data ***
                var fieldList = new List<DataField>();
                var ignoreList = new List<DataField>();
                var fieldIndexMap = new List<int>();
                var pkIndexMap = new List<int>();
                if (fieldFilter != null)
                {
                    foreach (var fieldName in fieldFilter)
                        if (!string.IsNullOrWhiteSpace(fieldName))
                        {
                            var field = viewPage.FindField(Convert.ToString(fieldName));
                            if (field == null)
                                RESTfulResource.ThrowError(400, true, "invalid_argument", "Unexpected field '{0}' is specified in the 'fields' parameter.", fieldName);
                            fieldList.Add(field);
                            fieldIndexMap.Add(viewPage.IndexOfField(field.Name));
                        }
                    // add any missing primary key fields to the output
                    foreach (var pkField in resource.PK)
                        if (!fieldFilter.Contains(pkField.Name))
                        {
                            var field = viewPage.FindField(pkField.Name);
                            fieldList.Add(field);
                            fieldIndexMap.Add(viewPage.IndexOfField(field.Name));
                            ignoreList.Add(field);
                        }
                }
                else
                {
                    var enumeratedFields = new List<DataField>();
                    // enumerate primary keys
                    foreach (var field in viewPage.Fields)
                        if (field.IsPrimaryKey)
                        {
                            fieldList.Add(field);
                            fieldIndexMap.Add(viewPage.IndexOfField(field.Name));
                            enumeratedFields.Add(field);
                        }
                    // enumerate the data fields with alliases following the original
                    foreach (var field in viewPage.Fields)
                        if (!enumeratedFields.Contains(field))
                        {
                            fieldList.Add(field);
                            fieldIndexMap.Add(viewPage.IndexOfField(field.Name));
                            if (!string.IsNullOrEmpty(field.AliasName))
                            {
                                var aliasField = viewPage.FindField(field.AliasName);
                                if (aliasField != null)
                                {
                                    fieldList.Add(aliasField);
                                    fieldIndexMap.Add(viewPage.IndexOfField(aliasField.Name));
                                    enumeratedFields.Add(aliasField);
                                }
                            }
                        }
                }
                foreach (var fvo in resource.PK)
                    for (var fieldIndex = 0; (fieldIndex < fieldList.Count); fieldIndex++)
                        if (fieldList[fieldIndex].Name == fvo.Name)
                        {
                            pkIndexMap.Add(fieldIndex);
                            break;
                        }
                // convert the page to the result
                if ((viewPage.TotalRowCount >= 0) && resource.IsCollection)
                {
                    result.Add(new JProperty("count", viewPage.TotalRowCount));
                    if (args["page"] != null)
                        result.Add(new JProperty("page", Convert.ToInt32(args["page"])));
                }
                if (fieldList.Count > 0)
                {
                    // *** return the blob ***
                    if ((!string.IsNullOrEmpty(resource.Field) && (fieldList.Count > resource.PK.Count)) && (fieldList[0].OnDemand && !string.IsNullOrEmpty(fieldList[0].OnDemandHandler)))
                    {
                        if (resource.IsImmutable)
                        {
                            if (cacheItem.IsMatch)
                                cacheItem.SetMaxAge();
                            Blob.Send(fieldList[0].OnDemandHandler, resource.Id);
                            if (response.StatusCode == 200)
                            {
                                ClearHeaders();
                                response.End();
                            }
                            else
                            {
                                response.Cache.SetMaxAge(TimeSpan.FromSeconds(0));
                                RESTfulResource.ThrowError(404, "invalid_path", "The blob value is not available.");
                            }
                        }
                    }
                    // *** continue to enumerate the resource objects ***
                    if ((limit == null) || (Convert.ToInt32(args["limit"]) > 0))
                    {
                        var objects = new JArray();
                        foreach (var row in viewPage.Rows)
                            objects.Add(resource.RowToObject(fieldList, ignoreList, row, pkIndexMap, fieldIndexMap));
                        if ((viewPage.PageSize == 1) && !string.IsNullOrEmpty(resource.Id))
                        {
                            if (objects.Count > 0)
                                foreach (var objProp in objects[0])
                                    result.Add(objProp);
                            else
                                RESTfulResource.ThrowError(404, "invalid_path", "The entity at {0} does not exist.", resource.ReplaceRawUrlWith(resource.PrimaryKeyToPath(), false, resource.PrimaryKeyToPath()));
                        }
                        else
                        {
                            if (resource.OutputContentType.Contains("xml"))
                                result.Add(new JProperty(resource.CollectionKey, new JObject(new JProperty(resource.XmlItem, objects))));
                            else
                                result.Add(new JProperty(resource.CollectionKey, objects));
                        }
                    }
                    // include the "_schema" key
                    if (resource.RequiresSchema && !resource.RequiresData)
                    {
                        var schemaTarget = result;
                        var collection = ((JArray)(result[resource.CollectionKey]));
                        if (collection != null)
                        {
                            if (collection.Count > 0)
                                schemaTarget = ((JObject)(collection.First));
                            else
                                schemaTarget = null;
                        }
                        if (schemaTarget != null)
                        {
                            var propsToRemove = new List<string>();
                            foreach (var propName in schemaTarget.Properties())
                                if (propName.Name != resource.SchemaKey && propName.Name != resource.LinksKey)
                                    propsToRemove.Add(propName.Name);
                            foreach (var propName in propsToRemove)
                                schemaTarget.Remove(propName);
                            if (collection != null)
                                result[resource.CollectionKey] = new JArray(schemaTarget);
                        }
                    }
                    // add "aggregate" to the result
                    if (viewPage.Aggregates != null)
                    {
                        resource.Hypermedia = false;
                        var aggregateObj = resource.RowToObject(fieldList, ignoreList, viewPage.Aggregates, pkIndexMap, fieldIndexMap);
                        result.Add(new JProperty("aggregates", aggregateObj));
                    }
                }
                if (!r.DoesNotRequireAggregates && (viewPage.Aggregates == null))
                    result.Add(new JProperty("aggregates", null));
                if (resource.Hypermedia && string.IsNullOrEmpty(resource.PathKey))
                {
                    var links = resource.CreateLinks(result);
                    // build the pager parameters (limit, fields, filter, sort)
                    var pagerLimit = Convert.ToInt32(args["limit"]);
                    if (pagerLimit == 0)
                        pagerLimit = resource.PageSize;
                    var pagerPage = Convert.ToInt32(args["page"]);
                    var pagerLast = Math.Ceiling(((viewPage.TotalRowCount / Convert.ToDouble(pagerLimit)) - 1));
                    if (args["page"] == null)
                    {
                        resource.AddLink("selfLink", "GET", links, resource.RawUrl);
                        resource.AddLink("firstLink", "GET", links, resource.ExtendRawUrlWith(true, "?page=0&limit={0}", resource.PageSize));
                        foreach (var viewId in resource.EnumerateViews("collection", resource.View))
                            if (!string.IsNullOrEmpty(resource.View))
                            {
                                var viewName = viewId;
                                var viewPath = viewId;
                                if (viewName == resource.DefaultView("collection"))
                                {
                                    viewName = "default";
                                    viewPath = string.Empty;
                                }
                                if (!string.IsNullOrEmpty(viewPath))
                                    viewPath = ("/" + viewPath);
                                viewName = resource.ToPathName(viewName);
                                viewPath = resource.ToPathName(viewPath);
                                resource.AddLink("selfLink", viewName, "GET", links, resource.ReplaceRawUrlWith(resource.ControllerResource, true, "{0}{1}", resource.ControllerResource, viewPath));
                                resource.AddLink("firstLink", viewName, "GET", links, resource.ReplaceRawUrlWith(resource.ControllerResource, true, "{0}{1}?page=0&limit={2}", resource.ControllerResource, viewPath, resource.PageSize));
                            }
                    }
                    else
                    {
                        if (viewPage.TotalRowCount > -1)
                        {
                            resource.AddLink("selfLink", "GET", links, resource.RawUrl);
                            if (pagerPage > 0)
                            {
                                resource.AddLink("firstLink", "GET", links, resource.ExtendRawUrlWith(true, "?page=0&limit={0}", pagerLimit));
                                resource.AddLink("prevLink", "GET", links, resource.ExtendRawUrlWith(true, "?page={0}&limit={1}", (pagerPage - 1), pagerLimit));
                            }
                            if (pagerPage < pagerLast)
                                resource.AddLink("nextLink", "GET", links, resource.ExtendRawUrlWith(true, "?page={0}&limit={1}", (pagerPage + 1), pagerLimit));
                            if (pagerPage < pagerLast)
                                resource.AddLink("lastLink", "GET", links, resource.ExtendRawUrlWith(true, "?page={0}&limit={1}", pagerLast, pagerLimit));
                        }
                    }
                    if (!string.IsNullOrEmpty(resource.LastEntity))
                        resource.CreateUpLink(links);
                    foreach (var field in viewPage.Fields)
                        if (!string.IsNullOrEmpty(field.ItemsDataController))
                            resource.CreateLookupLink(field, links);
                    resource.EnumerateActions(links);
                    resource.CreateSchemaLink(links);
                }
                if (resource.Hypermedia)
                {
                    var embedQueryParam = new NameSetParser(resource.EmbedParam, args).Execute();
                    if (embedQueryParam != null)
                        foreach (var name in embedQueryParam)
                        {
                            var allFields = (name + ".*");
                            if (!embed.Contains(allFields))
                                embed.Add(allFields);
                        }
                    if (embed.Count > 0)
                    {
                        var ee = new EmbeddingEngine(result, embed, resource);
                        ee.Execute();
                    }
                    if (resource.RemoveLinks)
                        resource.RemoveLinksFrom(result);
                }
            }
            catch (RESTfulResourceException ex)
            {
                if (ex.HttpCode > 0)
                    response.StatusCode = ex.HttpCode;
                else
                    response.StatusCode = 400;
                result = ApplicationServicesBase.Current.JsonError(ex, args, ex.Error, ex.Message);
                if (ex.SchemaHint)
                    resource.RequiresSchema = true;
            }
            catch (ThreadAbortException ex)
            {
                // The response was ended - do nothing
                throw ex;
            }
            catch (Exception ex)
            {
                result = ApplicationServicesBase.Current.JsonError(ex, args, "general_error", ex.Message);
            }
            finally
            {
                if (resource != null)
                    resource.AddSchema(result);
            }
            if ((cacheItem != null) && cacheItem.IsMatch)
            {
                cacheItem.Value = result;
                resource.AddLatestVersionLink(result, cacheItem);
                if (cacheItem.HasValue)
                    cacheItem.SetMaxAge();
            }
            return result;
        }

        private string ToSortExpression(JToken sort, RESTfulResource resource)
        {
            string sortExpression = null;
            if (sort != null)
            {
                sortExpression = string.Join(",", PropToStringArray(sort, false)).Trim();
                if (!Regex.IsMatch(sortExpression, "^\\w+(\\s+\\w+)?(\\s*,\\s*\\w+(\\s+\\w+)?)?$"))
                    RESTfulResource.ThrowError("invalid_argument", "Invalid 'sort' parameter.");
                foreach (Match m in Regex.Matches(sortExpression, "(\\w+)(\\s+(\\w+))?"))
                {
                    if (!resource.FieldMap.ContainsKey(m.Groups[1].Value))
                        RESTfulResource.ThrowError(400, true, "invalid_argument", "Unexpected field '{0}' is specified in the '{1}' parameter.", m.Groups[1].Value, resource.ToApiName("sort"));
                    if (!Regex.IsMatch(m.Groups[3].Value, "^(asc|desc|\\s*)$"))
                        RESTfulResource.ThrowError("invalid_argument", "Invalid sort order '{0}' is specified in the '{1}' parameter.", m.Groups[3].Value, resource.ToApiName("sort"));
                }
            }
            return sortExpression;
        }

        public virtual object GraphQLExecute(DataControllerService service, JObject args)
        {
            var query = args["query"];
            if (query == null)
                return null;
            var result = new JObject();
            try
            {
                var data = new JProperty("data");
                result.Add(data);
            }
            catch (Exception ex)
            {
                result.Add(new JProperty("errors", new JArray(new JProperty("message", ex.Message))));
            }
            return result;
        }

        public override JObject Parse(string args)
        {
            var request = HttpContext.Current.Request;
            var contentType = request.ContentType;
            // process HTML form
            if (contentType == "application/x-www-form-urlencoded")
            {
                var form = new JObject();
                foreach (string key in request.Form.Keys)
                {
                    var v = request.Form[key].Trim();
                    if (!string.IsNullOrEmpty(v))
                        form.Add(new JProperty(key, v));
                }
                return form;
            }
            // process mulitpart form-data
            if (contentType.StartsWith("multipart/form-data;"))
            {
                string suspectedPayload = null;
                var suspectedPayloadCount = 0;
                for (var i = 0; (i < request.Files.Count); i++)
                {
                    var f = request.Files[i];
                    if (string.IsNullOrWhiteSpace(f.FileName))
                    {
                        if (IsPayloadContentType(f.ContentType))
                            suspectedPayloadCount++;
                        if (!IsPayloadContentType(f.ContentType) || (suspectedPayloadCount > 1))
                            RESTfulResource.ThrowError(400, true, "invalid_form_data", "File data without a name is not allowed.");
                    }
                }
                JObject form = null;
                string payload = null;
                string payloadContentType = null;
                string payloadName = null;
                var boundary = Regex.Match(contentType, "\\bboundary=(.+)(;|$)");
                if (!boundary.Success)
                    RESTfulResource.ThrowError("invalid_form_data", "Missing boundary in the content type.");
                var formDataRegex = new Regex(string.Format("--{0}\\r\\nContent-Disposition:\\s*form-data;\\s*name=\"(?\'Name\'(|[\\s\\S]+?))\"(;(?'Disposition'.+?))?\\r\\n(Content-Type:\\s*(?'ContentType'.+?)\\r\\n)?\\r\\n(\\r\\n|(?'Value'|[\\s\\S]+?)\\r\\n)(?=((--{0}|$)))", Regex.Escape(boundary.Groups[1].Value)), RegexOptions.IgnoreCase);
                var formData = formDataRegex.Match(args);
                var specifiedNames = new List<string>();
                while (formData.Success)
                {
                    var name = formData.Groups["Name"].Value;
                    if (Regex.IsMatch(name, "[^\\w_]"))
                        RESTfulResource.ThrowError("invalid_form_data", "Value '{0}' includes non-alphanumeric characters in the name.", name);
                    if (specifiedNames.Contains(name))
                        RESTfulResource.ThrowError("invalid_form_data", "Value with the name '{0}' is specified more than once.", name);
                    specifiedNames.Add(name);
                    var value = formData.Groups["Value"].Value;
                    var disposition = formData.Groups["Disposition"].Value;
                    var dataContentType = formData.Groups["ContentType"].Value;
                    if (string.IsNullOrEmpty(name))
                    {
                        if (string.IsNullOrEmpty(dataContentType))
                            suspectedPayload = value;
                        else
                        {
                            if (payload != null)
                                RESTfulResource.ThrowError("invalid_form_data", "Duplicate '{0}' payload is specified.", dataContentType);
                            if (form != null)
                                RESTfulResource.ThrowError("invalid_form_data", "Payload '{0}' cannot be specified after the named values in the 'multipart/form-data' body.", dataContentType);
                            payload = value;
                            payloadContentType = dataContentType;
                            payloadName = payloadContentType;
                        }
                    }
                    else
                    {
                        if (Regex.IsMatch(name, "^[\\w_]+$"))
                        {
                            if (string.IsNullOrEmpty(dataContentType))
                            {
                                if (payload != null)
                                    RESTfulResource.ThrowError("invalid_form_data", "Specify '{0}' value in the payload '{1}' instead.", name, payloadName);
                                if (form == null)
                                    form = new JObject();
                                form[name] = value;
                            }
                            else
                            {
                                if (string.IsNullOrEmpty(disposition))
                                {
                                    if ((payload != null) || (form != null))
                                        RESTfulResource.ThrowError("invalid_form_data", "Unexpected payload '{0}' is specified.", name);
                                    payload = value;
                                    payloadContentType = dataContentType;
                                    payloadName = name;
                                }
                            }
                        }
                    }
                    formData = formData.NextMatch();
                }
                if (form != null)
                    return form;
                if (string.IsNullOrEmpty(payloadContentType))
                {
                    if (!string.IsNullOrEmpty(suspectedPayload))
                    {
                        payload = suspectedPayload;
                        payloadContentType = "application/json";
                    }
                    else
                        return new JObject();
                }
                contentType = payloadContentType;
                if ((payloadContentType == "application/xml") || (payloadContentType == "text/xml"))
                    args = TextUtility.XmlToJson(payload);
                else
                    args = payload;
            }
            // verify the content type and return the payload
            if (string.IsNullOrEmpty(contentType))
                contentType = "application/json";
            if (!IsPayloadContentType(contentType))
                RESTfulResource.ThrowError("invalid_content_type", "Content type '{0}' is not supported in the request.", contentType);
            return TextUtility.ParseYamlOrJson(args, true);
        }

        public static bool IsPayloadContentType(string contentType)
        {
            return Regex.IsMatch(contentType, "^(application/(json|x-yaml|xml)|text/(yaml|x-yaml|xml))$");
        }
    }
}
