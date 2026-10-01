(function (window) {
  'use strict';

  var noop = function () {};

  if (!window.mixpanel) {
    window.mixpanel = {
      init: noop,
      track: noop,
      identify: noop,
      people: {
        set: noop,
        increment: noop,
        append: noop
      }
    };
  }
})(window);
