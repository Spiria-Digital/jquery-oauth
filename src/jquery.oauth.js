var jqOAuth = function jqOAuth(options) {
    this.options = {};
    this.data = {};
    this.intercept = false;
    this.refreshing = false;
    this.buffer = [];
    this.currentRequests = [];

    this._resetOptions();
    this._setupInterceptor();

    $.extend(this.options, options);

    if (this._hasStoredData()) {
        this._getStoredData();

        if (this.hasAccessToken()) {
            this.login(this.data.accessToken);
        }
    } else {
        this._resetData();
        this._updateStorage();
    }
}

// Public methods

jqOAuth.prototype.getAccessToken = function getAccessToken() {
    return this.data.accessToken;
};

jqOAuth.prototype.hasAccessToken = function hasAccessToken() {
    return this.data.accessToken !== null;
};

jqOAuth.prototype.logout = function logout() {
    this._resetData();
    this._updateStorage();
    this._deactivateInterceptor();
    this._fireEvent("logout");
};

jqOAuth.prototype.login = function login(accessToken) {
    this.setAccessToken(accessToken);

    this._activateInterceptor();
    this._fireEvent("login");
};

jqOAuth.prototype.setAccessToken = function setAccessToken(accessToken) {
    this.data.accessToken = accessToken;
    this._updateStorage();
};

jqOAuth.prototype.setCsrfToken = function setCsrfToken(csrfToken) {
    this.options.csrfToken = csrfToken;
};

// Private methods

jqOAuth.prototype._activateInterceptor = function _activateInterceptor() {
    this.intercept = true;
};

jqOAuth.prototype._addToBuffer = function _addToBuffer(settings, deferred) {
    this.buffer.push({
        deferred: deferred,
        settings: settings
    });
};

jqOAuth.prototype._clearBuffer = function _clearBuffer() {
    this.buffer = [];
};

jqOAuth.prototype._deactivateInterceptor = function _deactivateInterceptor() {
    this.intercept = false;
};

jqOAuth.prototype._fireBuffer = function _fireBuffer() {
    var self = this;
    var deferred;
    var promises = [];

    for(var i in this.buffer) {
        deferred = this.buffer[i].deferred;

        this.buffer[i].settings.refreshRetry = true;
        promises.push($.ajax(this.buffer[i].settings).then(deferred.resolve, deferred.reject));
    }

    this._clearBuffer();

    $.when.apply($, promises)
        .done(function() {
            self._setRefreshingFlag(false);
        })
        .fail(function(){
            self._setRefreshingFlag(false);
            self.logout();
        });
};

jqOAuth.prototype._fireEvent = function _fireEvent(eventType) {
    if (this._hasEvent(eventType)) {
        return this.options.events[eventType]();
    }
};

jqOAuth.prototype._getStoredData = function _getStoredData() {
    $.extend(this.data, storage.get(this.options.tokenName));
};

jqOAuth.prototype._hasEvent = function _hasEvent(eventType) {
    return this.options.events[eventType] !== undefined && typeof this.options.events[eventType] === "function";
};

jqOAuth.prototype._hasFilter = function _hasFilter(filterType) {
    return this.options.filters[filterType] !== undefined && typeof this.options.filters[filterType] === 'function';
}

jqOAuth.prototype._hasStoredData = function _hasStoredData() {
    return storage.get(this.options.tokenName) !== undefined;
};

jqOAuth.prototype._resetData = function _resetData() {
    this.data = {
        accessToken: null
    };
};

jqOAuth.prototype._resetOptions = function _resetOptions() {
    this.options = {
        bufferInterval: 25,
        bufferWaitLimit: 500,
        csrfToken: null,
        events: {},
        tokenName: 'jquery.oauth',
        filters : {}
    };
};

jqOAuth.prototype._setAjaxHeader = function _setAjaxHeader(header, value) {
    if (!this._isAjaxHeadersInitialized()) {
        $.ajaxSettings.headers = {};
    }

    $.ajaxSettings.headers[header] = value;
};

jqOAuth.prototype._setRefreshingFlag = function _setRefreshingFlag(newFlag) {
    this.refreshing = newFlag;
};

jqOAuth.prototype._hasCSRFToken = function _hasCSRFToken() {
    return this.options.csrfToken;
}

jqOAuth.prototype._setupInterceptor = function _setupInterceptor() {
    var self = this;

    // Credits to gnarf @ http://stackoverflow.com/a/12446363/602488
    $.ajaxPrefilter(function(options, originalOptions, jqxhr) {
        if (self._shouldAddAuthorization(options)) {
            jqxhr.setRequestHeader('Authorization', 'Bearer ' + self.data.accessToken);
        }

        if (self._hasCSRFToken()) {
            jqxhr.setRequestHeader('X-CSRF-Token', this.options.csrfToken);
        }

        if (options.refreshRetry === true) {
            return;
        }

        var deferred = $.Deferred();

        self.currentRequests.push(options.url);
        jqxhr.always(function(){
            self.currentRequests.splice($.inArray(options.url, self.currentRequests), 1);
        });
        jqxhr.done(deferred.resolve);
        jqxhr.fail(function() {
            var args = Array.prototype.slice.call(arguments);

            if (self.intercept && jqxhr.status === 401 && self._hasEvent("tokenExpiration")) {
                self._addToBuffer(options, deferred);

                if (!self.refreshing) {
                    self._setRefreshingFlag(true);
                    self._fireEvent("tokenExpiration")
                        .success(function () {
                            // Setup buffer interval that waits for all sent requests to return
                            var waited   = 0;
                            self.interval = setInterval(function(){
                                waited += self.options.bufferInterval;

                                // All requests have returned 401 and have been buffered
                                if (self.currentRequests.length === 0 || waited >= self.options.bufferWaitLimit) {
                                    clearInterval(self.interval);
                                    self._fireBuffer();
                                }
                            }, self.options.bufferInterval);
                        })
                        .fail(function () {
                            self.logout();
                        });
                }
            } else {
                deferred.rejectWith(jqxhr, args);
            }
        });

        return deferred.promise(jqxhr);
    });
};

jqOAuth.prototype._shouldAddAuthorization = function _shouldAddAuthorization(prefilterOptions) {
    return !this._hasFilter('url') || this.options.filters.url(prefilterOptions.url);
};

jqOAuth.prototype._updateStorage = function _updateStorage() {
    storage.set(this.options.tokenName, this.data);
};
