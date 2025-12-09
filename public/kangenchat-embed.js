(function () {
  function getBaseUrl() {
    try {
      var script = document.currentScript;
      if (!script) return window.location.origin;
      var url = new URL(script.src);
      return url.origin;
    } catch (e) {
      return window.location.origin;
    }
  }

  function createIframe(baseUrl, options) {
    var url = new URL('/widget', baseUrl);
    url.searchParams.set('mode', options.mode || 'floating');
    if (options.primaryColor) url.searchParams.set('primaryColor', options.primaryColor);
    if (options.logoUrl) url.searchParams.set('logoUrl', options.logoUrl);
    if (options.welcomeTitle) url.searchParams.set('welcomeTitle', options.welcomeTitle);
    if (options.welcomeSubtitle) url.searchParams.set('welcomeSubtitle', options.welcomeSubtitle);

    var iframe = document.createElement('iframe');
    iframe.src = url.toString();
    iframe.style.width = '100%';
    iframe.style.height = '100%';
    iframe.style.border = 'none';
    iframe.setAttribute('allow', 'clipboard-write');
    iframe.setAttribute('title', options.title || 'Live Support');
    return iframe;
  }

  function ensureFloatingContainer() {
    var id = 'kangenchat-widget-container';
    var existing = document.getElementById(id);
    if (existing) return existing;
    var div = document.createElement('div');
    div.id = id;
    div.style.position = 'fixed';
    div.style.bottom = '16px';
    div.style.right = '16px';
    div.style.width = '384px';
    div.style.height = '512px';
    div.style.maxWidth = '100vw';
    div.style.maxHeight = '100vh';
    div.style.zIndex = '2147483647';
    document.body.appendChild(div);
    return div;
  }

  function mountFloating(baseUrl, options) {
    var container = ensureFloatingContainer();
    container.innerHTML = '';
    container.appendChild(createIframe(baseUrl, options));
  }

  function mountInline(baseUrl, options) {
    if (!options.containerId) {
      if (console && console.warn) console.warn('[KangenChat] inline mode requires containerId');
      return;
    }
    var el = document.getElementById(options.containerId);
    if (!el) {
      if (console && console.warn) console.warn('[KangenChat] container not found: ' + options.containerId);
      return;
    }
    el.innerHTML = '';
    el.style.position = el.style.position || 'relative';
    el.appendChild(createIframe(baseUrl, options));
  }

  var baseUrl = getBaseUrl();

  var api = {
    init: function (options) {
      options = options || {};
      var mode = options.mode || 'floating';
      if (mode === 'inline') {
        mountInline(baseUrl, options);
      } else {
        mountFloating(baseUrl, options);
      }
    }
  };

  window.KangenChat = window.KangenChat || {};
  for (var k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) {
      window.KangenChat[k] = api[k];
    }
  }
})();
