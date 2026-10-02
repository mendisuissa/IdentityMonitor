'use strict';
const { assertExecutionHeld } = require('./remediationApproval');

// Legacy SDK clients are read-only for remediation. Existing mail notification
// and subscription lifecycle calls are narrowly retained; neither grants a
// device/user/policy write capability. No SDK internals escape this facade.
function protectGraphClient(client) {
  return Object.freeze({
    api(path) {
      const notification = typeof path === 'string' && /^\/users\/[^/?#]+\/sendMail$/.test(path);
      const subscription = typeof path === 'string' && /^\/subscriptions(?:\/[a-zA-Z0-9-]+)?$/.test(path);
      const request = client.api(path);
      function wrap(current, mutationAllowed = true) {
        const facade = {};
        for (const method of ['get']) facade[method] = (...args) => current[method](...args);
        for (const method of ['post','patch','put','delete']) facade[method] = (...args) => {
          if (!mutationAllowed || !((notification && method === 'post') || (subscription && ['post','patch','delete'].includes(method)))) assertExecutionHeld();
          return current[method](...args);
        };
        for (const method of ['select','filter','orderby','top','skip','expand','count','version','header','headers','query']) facade[method] = (...args) => {
          if (method === 'version' && !['v1.0','beta'].includes(args[0])) assertExecutionHeld();
          // Chained URL/header/query alterations never retain a mail/subscription
          // write exemption. Existing lifecycle writers use exact direct paths.
          return wrap(current[method](...args), false);
        };
        return Object.freeze(facade);
      }
      return wrap(request);
    }
  });
}
module.exports = { protectGraphClient };
