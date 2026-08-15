const showLoginWithoutSSOProbe = showLogin

showLogin = function(message = '') {
 showLoginWithoutSSOProbe(message)
 detectSSOAvailability()
}

async function detectSSOAvailability() {
 try {
  const target = `/${location.hash || '#overview'}`
  const response = await fetch(`/auth/login?return_to=${encodeURIComponent(target)}`, { method: 'HEAD', redirect: 'manual', cache: 'no-store' })
  const enabled = response.status !== 404
  $('sso-login').hidden = !enabled
  $('login-sso-divider').hidden = !enabled
 } catch {
  $('sso-login').hidden = true
  $('login-sso-divider').hidden = true
 }
}
