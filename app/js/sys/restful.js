/*eslint eqeqeq: ["error", "smart"]*/
/*!
* Restful.js - RESTful Level 3 Client API
* Copyright 2022 Code On Time LLC; Licensed MIT; http://codeontime.com/license
*/

(function () {
    var _app = typeof $app == "undefined" ? null : $app,
        _window = window,
        config = {},
        baseUrl,
        _restful;
    if (!_app)
        _window.$app = _app = {};
    _restful = _app.restful;
    if (_restful && !_restful._unresolved)
        return;
    _restful = _app.restful = function (options) {
        if (!options)
            options = { url: null, method: 'GET', body: null };
        var optionsConfig = options.config,
            queryParams = options.query;
        config = optionsConfig || config;
        if (optionsConfig) {
            baseUrl = optionsConfig.baseUrl || baseUrl;
            if (Object.keys(options).length === 1)
                return;
        }
        if (!baseUrl) {
            baseUrl = typeof __baseUrl == 'undefined' ? null : __baseUrl;
            if (!baseUrl) {
                var allScripts = document.getElementsByTagName('script');
                for (var i = 0; i < allScripts.length; i++) {
                    var script = allScripts[i];
                    var me = (script.getAttribute('src') || '').match(/^(.+?)(\/v\d\/js|\/js\/sys)\/restful.*?\.js/);
                    if (me) {
                        baseUrl = me[1];
                        break;
                    }
                }
            }
        }
        var token = options.token || (options.token !== false && config.token ? (typeof config.token == 'function' ? config.token() : config.token) : null),
            accessToken = typeof token == 'string' ? token : token && typeof token == 'object' ? token.access_token : null;
        if (!accessToken && _app.AccountManager) {
            token = _app.AccountManager.current();
            if (token)
                accessToken = token.access_token;

        }
        // ****************************************************************************
        // debug only - simulates 401 http response that will require the token refresh
        // ****************************************************************************
        //var dummy = _window.dummy;
        //if (dummy == null)
        //    dummy = _window.dummy = 0;
        //if (accessToken != null && dummy % 2 == 0)
        //    accessToken += 'xyz';
        //_window.dummy++;
        // ****************************************************************************
        // end debug
        // ****************************************************************************

        if (options.url && options.url.href) {
            options.method = options.url.method;
            options.url = options.url.href;
        }

        var url = options.url || '/v2';

        if (!url.match(/^http/) && baseUrl) {
            if (!url.match(/^\//))
                url = '/' + url;
            if (baseUrl != '/')
                url = baseUrl + url;
        }
        if (queryParams) {
            url = [url];
            for (var paramName in queryParams)
                url.push(url.length === 1 ? url[0].match(/\?|#/) ? '&' : '?' : '&', paramName, '=', encodeURIComponent(queryParams[paramName]));
            url = url.join('')
        }

        var promise = new Promise((resolve, reject) => {
            var myHeaders = new Headers(),
                method = options.method || 'GET',
                hypermedia = options.hypermedia,
                schema;
            if (accessToken)
                myHeaders.append('Authorization', 'Bearer ' + accessToken);
            myHeaders.append("Accept", options.accept || "application/json");
            if (method !== 'GET')
                myHeaders.append("Content-Type", options.contentType || "application/json");
            if (options.headers)
                for (var name in options.headers)
                    myHeaders.append(name, options.headers[name]);
            if (options.schema)
                schema = 'true';
            if (options.schemaOnly)
                schema = 'only';
            if (schema)
                myHeaders.append('X-Restful-Schema', schema);
            if (hypermedia === false)
                myHeaders.append('X-Restful-Hypermedia', 'false');
            if (typeof hypermedia == 'string' && hypermedia.length) {
                var m = hypermedia.match(/^(.+?)(\s*(>>)\s*(.*))?$/);
                if (m) {
                    hypermedia = { name: m[1], transition: !!m[3], next: m[4] };
                    if (hypermedia.transition) {
                        for (var key in ['body', 'query', 'headers', 'files'])
                            delete options[key];
                        var hre = new RegExp(RegExp('^' + hypermedia.name + '\\s*>>'));
                        for (var key in options)
                            if (key.match(hre)) {
                                var hypermediaData = options[key];
                                if (hypermediaData)
                                    for (var key in hypermediaData)
                                        options[key] = hypermediaData[key];
                                break;
                            }
                    }
                }
            }

            var body = options.body,
                etag = options.etag,
                blobs,
                bodyLinks;
            if (body && typeof body == 'object') {
                if (etag === true) {
                    bodyLinks = body._links;
                    etag = bodyLinks && bodyLinks.self && bodyLinks.self.etag;
                }
                for (var fieldName in body) {
                    var fieldValue = body[fieldName];
                    if (fieldValue instanceof Blob) {
                        if (!blobs)
                            blobs = [];
                        blobs.push({ f: fieldName, v: fieldValue });
                    }
                }
                if (blobs) {
                    blobs.forEach(b => delete body[b.f]);
                    myHeaders.delete('Content-Type');
                }
                body = JSON.stringify(body);
            }

            if (typeof etag == 'string')
                myHeaders.append('If-Match', etag);

            if (blobs) {
                var formdata = new FormData();
                //formdata.set('', body);
                formdata.set('', new Blob([body], { type: 'application/json' }), '');
                blobs.forEach(b =>
                    formdata.set(b.f, b.v, b.v.name || '')
                );
                body = formdata;
            }

            var requestOptions = {
                method: method,
                headers: myHeaders,
                body: method === 'GET' ? null : body,
                redirect: 'follow'
            };

            var responseStatus,
                contentType,
                contentDisposition,
                etag,
                isText;

            function tryAfterTokenRefresh(token) {
                options.token = token;
                _restful(options)
                    .then(result => {
                        if (resolve)
                            resolve(result);
                    })
                    .catch(restfulException);
            }

            function restfulException(error) {
                if (reject)
                    reject(error.error || error);
            }

            fetch(url, requestOptions)
                .then(function (response) {
                    responseStatus = response.status;
                    contentType = response.headers.get("Content-Type");
                    contentDisposition = response.headers.get("Content-Disposition");
                    etag = response.headers.get("ETag");
                    isText = responseStatus !== 401 && contentType.match(/^(application\/(json|x-yaml|xml)|text\/(yaml|x-yaml|xml))/);
                    return isText ? response.text() : response.arrayBuffer();
                })
                .then(result => {
                    if (responseStatus === 401) {
                        if (token && token.refresh_token) {
                            if (_app.refreshUserToken) {
                                _app.refreshUserToken(token, () => {
                                    tryAfterTokenRefresh(_app.AccountManager.current());
                                });
                            }
                            else {
                                _restful({
                                    url: '/oauth2/v2/token',
                                    method: 'POST',
                                    body: {
                                        grant_type: 'refresh_token',
                                        client_id: config.clientId,
                                        refresh_token: token.refresh_token
                                    },
                                    token: false
                                })
                                    .then(result => {
                                        if (typeof config.token == 'function') {
                                            var newToken = config.token()
                                            if (typeof newToken == 'object') {
                                                for (var propName in result)
                                                    newToken[propName] = result[propName];
                                            }
                                            config.token(newToken);
                                        }
                                        options.token = result;
                                        tryAfterTokenRefresh(result);
                                    })
                                    .catch(restfulException);
                            }
                        }
                        else
                            restfulException(createError(401, 'Unauthorized', 'access_denied', 'Invalid acces token or API key is specified.'));
                    }
                    else if (resolve) {
                        if (isText && contentType.match(/^application\/json/)) {
                            if (result == null || !result.length)
                                result = "{}";
                            result = JSON.parse(result);
                            if (result && result.error) {
                                result.error._schema = result._schema;
                                restfulException(result.error);
                            }
                            else {
                                if (etag && result._links) {
                                    var self = result._links.self;
                                    if (self)
                                        self.etag = etag;
                                }
                                if (hypermedia && hypermedia.name) {
                                    result = result._links ? result._links[hypermedia.name] : null;
                                    if (result == null)
                                        restfulException(createError(400, 'Bad Request', 'invalid_hypermedia', "Hypermedia '" + hypermedia[1] + "' not found in " + method + " " + url + ' response.'));
                                    else if (hypermedia.transition) {
                                        options.url = result;
                                        options.hypermedia = hypermedia.next;
                                        _restful(options)
                                            .then(result => {
                                                resolve(result);
                                            })
                                            .catch(restfulException);
                                        return;
                                    }
                                }
                                if (hypermedia === true)
                                    result = result._links || {};
                                resolve(result || {});
                            }
                        }
                        else {
                            if (!isText) {
                                var filename = 'file.' + (contentType.split(';')[0] || '/dat').split(/\//)[1];
                                if (contentDisposition) {
                                    var fn = contentDisposition.match(/filename=(.+?)(;|$)/);
                                    if (fn)
                                        filename = fn[1];

                                }
                                result = new Blob([result], { type: contentType });
                                result.name = filename;
                            }
                            resolve(result);
                        }
                    }
                })
                .catch(error => {
                    restfulException(createError(400, 'Bad Request', 'error', error));
                });
        });
        return promise;
    };

    function createError(httpCode, httpMessage, reason, error) {
        return {
            error: {
                errors: [
                    {
                        id: "00000000-0000-0000-0000-000000000001",
                        reason: reason,
                        message: error.message || error
                    }],
                code: httpCode,
                message: httpMessage
            }
        }
    }
})();