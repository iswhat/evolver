'use strict';

const { getProxyToken, getProxyUrl } = require('./server/settings');

function isDisabled(env = process.env) {
  const raw = String(env.EVOMAP_PROXY_AUTO_INJECT || '').trim().toLowerCase();
  return raw === '0' || raw === 'false' || raw === 'off' || raw === 'none' || raw === 'no';
}

function injectProxyEnv(info = {}, env = process.env) {
  if (isDisabled(env)) {
    return { injected: false, reason: 'disabled' };
  }

  const useSettingsFallback = env === process.env && info.useSettings !== false;
  const url = String(info.url || (useSettingsFallback ? getProxyUrl() : '') || '').replace(/\/+$/, '');
  const token = String(info.token || (useSettingsFallback ? getProxyToken() : '') || '');
  if (!url || !token) {
    return { injected: false, reason: 'missing_proxy_settings' };
  }

  const currentBase = String(env.ANTHROPIC_BASE_URL || '').trim().replace(/\/+$/, '');
  if (currentBase && currentBase !== url && !env.EVOMAP_ANTHROPIC_BASE_URL) {
    env.EVOMAP_ANTHROPIC_BASE_URL = currentBase;
  }
  const currentAuthToken = String(env.ANTHROPIC_AUTH_TOKEN || '').trim();
  if (currentAuthToken && currentAuthToken !== token && !env.EVOMAP_ANTHROPIC_AUTH_TOKEN) {
    env.EVOMAP_ANTHROPIC_AUTH_TOKEN = currentAuthToken;
  }

  env.ANTHROPIC_BASE_URL = url;
  env.ANTHROPIC_AUTH_TOKEN = token;
  env.CUSTOM_API_KEY = token;
  env.EVOMAP_PROXY_URL = url;
  env.EVOMAP_PROXY_AUTO_INJECTED = '1';

  return {
    injected: true,
    url,
    vars: [
      'ANTHROPIC_BASE_URL',
      'ANTHROPIC_AUTH_TOKEN',
      'CUSTOM_API_KEY',
      'EVOMAP_PROXY_URL',
    ],
  };
}

module.exports = {
  injectProxyEnv,
  isDisabled,
};
